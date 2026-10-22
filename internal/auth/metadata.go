package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const maxMetadataBytes = 1 << 20

// Fetch must enforce a same-origin redirect policy and a bounded redirect count.
type Fetch func(context.Context, string) (*http.Response, error)

type metadataEntry struct {
	done   chan struct{}
	data   []byte
	status int
	err    error
}

// Resolver is scoped to one endpoint probe. Concurrent observations share at most
// three unique metadata requests and the caller's existing endpoint deadline.
type Resolver struct {
	mu    sync.Mutex
	cache map[string]*metadataEntry
	fetch Fetch
}

func NewResolver(fetch Fetch) *Resolver {
	return &Resolver{cache: make(map[string]*metadataEntry), fetch: fetch}
}

// Enrich leaves the access state unchanged. A bearer challenge alone is not OAuth evidence.
func (r *Resolver) Enrich(ctx context.Context, o Observation) Observation {
	endpoint, err := url.Parse(o.URL)
	if err != nil || !validHTTPURL(endpoint) {
		return o
	}
	type candidate struct{ url, source string }
	var candidates []candidate
	for _, c := range o.Challenges {
		if c.ParseError == "" {
			if ref, ok := c.Parameters["resource_metadata"]; ok {
				candidates = append(candidates, candidate{ref, "challenge"})
			}
		}
	}
	// Well-known fallbacks are useful for bare/Bearer 401s, rather than Basic-only gateways.
	bearer := false
	for _, c := range o.Challenges {
		if c.ParseError == "" && strings.EqualFold(c.Scheme, "Bearer") {
			bearer = true
		}
	}
	if len(candidates) == 0 && (bearer || o.HTTPStatus == 401 && len(o.Schemes) == 0) {
		path := *endpoint
		path.Path = "/.well-known/oauth-protected-resource" + strings.TrimSuffix(endpoint.Path, "/")
		path.RawPath = ""
		if endpoint.RawPath != "" {
			path.RawPath = "/.well-known/oauth-protected-resource" + strings.TrimSuffix(endpoint.EscapedPath(), "/")
		}
		candidates = append(candidates, candidate{path.String(), "well_known_endpoint"})
		root := *endpoint
		root.Path, root.RawPath, root.RawQuery, root.ForceQuery = "/.well-known/oauth-protected-resource", "", "", false
		candidates = append(candidates, candidate{root.String(), "well_known_root"})
	}
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		if seen[candidate.url] {
			continue
		}
		seen[candidate.url] = true
		result := ResourceMetadata{URL: candidate.url, Source: candidate.source}
		u, err := url.Parse(candidate.url)
		if err != nil || !validHTTPURL(u) {
			result.State, result.Error = "invalid", "invalid metadata URL"
		} else if !SameOrigin(endpoint, u) {
			result.State = "external"
		} else if ctx.Err() != nil {
			result.State, result.Error = "not_attempted", ctx.Err().Error()
		} else {
			entry := r.get(ctx, u.String())
			result.HTTPStatus = entry.status
			if entry.err != nil {
				result.State, result.Error = "unavailable", entry.err.Error()
			} else {
				result = validateMetadata(result, entry.data, o.URL)
			}
		}
		o.Metadata = append(o.Metadata, result)
		if result.State == "validated" {
			o.OAuthAdvertised = true
			break
		}
	}
	return o
}

func validHTTPURL(u *url.URL) bool {
	return u != nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}

// SameOrigin includes the scheme and effective port, not just the hostname.
func SameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

func (r *Resolver) get(ctx context.Context, endpoint string) metadataEntry {
	r.mu.Lock()
	if existing := r.cache[endpoint]; existing != nil {
		r.mu.Unlock()
		select {
		case <-existing.done:
			return *existing
		case <-ctx.Done():
			return metadataEntry{err: ctx.Err()}
		}
	}
	if len(r.cache) == 3 {
		r.mu.Unlock()
		return metadataEntry{err: fmt.Errorf("metadata request limit reached")}
	}
	entry := &metadataEntry{done: make(chan struct{})}
	r.cache[endpoint] = entry
	r.mu.Unlock()
	defer close(entry.done)
	resp, err := r.fetch(ctx, endpoint)
	if err != nil {
		entry.err = err
		return *entry
	}
	defer resp.Body.Close()
	entry.status = resp.StatusCode
	u, _ := url.Parse(endpoint)
	if resp.Request == nil || !validHTTPURL(resp.Request.URL) || !SameOrigin(u, resp.Request.URL) {
		entry.err = fmt.Errorf("metadata response left its origin")
		return *entry
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != 200 || ct != "application/json" {
		entry.err = fmt.Errorf("not JSON metadata (HTTP %d)", resp.StatusCode)
		return *entry
	}
	entry.data, entry.err = io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if len(entry.data) > maxMetadataBytes {
		entry.err = fmt.Errorf("metadata exceeds 1 MiB")
	}
	return *entry
}

func validateMetadata(result ResourceMetadata, data []byte, endpoint string) ResourceMetadata {
	var doc struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		ScopesSupported        []string `json:"scopes_supported"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		result.State, result.Error = "invalid", "invalid resource metadata JSON"
		return result
	}
	if doc.Resource != endpoint {
		result.State, result.Error = "invalid", "metadata resource does not match the protected endpoint"
		return result
	}
	for _, issuer := range doc.AuthorizationServers {
		u, err := url.Parse(issuer)
		if err != nil || !validHTTPURL(u) || u.Scheme != "https" || u.RawQuery != "" {
			result.State, result.Error = "invalid", "invalid advertised authorization-server URL"
			return result
		}
	}
	result.State, result.Resource = "validated", doc.Resource
	result.AuthorizationServers, result.ScopesSupported, result.BearerMethodsSupported = doc.AuthorizationServers, doc.ScopesSupported, doc.BearerMethodsSupported
	return result
}
