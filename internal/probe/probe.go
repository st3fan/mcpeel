// Package probe confirms MCP endpoints using bounded HTTP and legacy SSE exchanges.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/st3fan/mcpeel/internal/targets"
)

const modernVersion = "2026-07-28"

var legacyVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// ServerInfo is untrusted, self-reported metadata from the server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Prober is safe for concurrent use. Its configuration must not change during a scan.
type Prober struct {
	client  *http.Client
	timeout time.Duration
}

func New(timeout time.Duration) *Prober {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 10
	return &Prober{
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
		timeout: timeout,
	}
}

func (p *Prober) Close() { p.client.CloseIdleConnections() }

// Probe checks both transports concurrently within one deadline, including HTTP
// fallback and protocol retries. Distinct redirect destinations remain separate findings.
// Cleanup has its own short deadline and still respects caller cancellation.
func (p *Prober) Probe(parent context.Context, c targets.Candidate) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(parent, p.timeout)
	defer cancel()
	f, err, connectionFailure := p.probeURL(ctx, parent, c.URL)
	if len(f) == 0 && connectionFailure && c.Fallback && strings.HasPrefix(c.URL, "https://") && ctx.Err() == nil {
		f, err, _ = p.probeURL(ctx, parent, "http://"+strings.TrimPrefix(c.URL, "https://"))
	}
	for i := range f {
		f[i].Input = c.Input
	}
	return f, err
}

func requestBody(method, version string) []byte {
	params := map[string]any{}
	if method == "server/discover" {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    version,
			"io.modelcontextprotocol/clientInfo":         ServerInfo{Name: "mcpeel", Version: "0.1.0"},
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}
	} else {
		params["protocolVersion"] = version
		params["capabilities"] = map[string]any{}
		params["clientInfo"] = ServerInfo{Name: "mcpeel", Version: "0.1.0"}
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": method, "method": method, "params": params})
	return b
}

func headers(method, version, session string) http.Header {
	h := http.Header{}
	h.Set("Accept", "application/json, text/event-stream")
	h.Set("Content-Type", "application/json")
	h.Set("User-Agent", "mcpeel/0.1.0")
	if method != "" {
		h.Set("Mcp-Method", method)
	}
	if version != "" {
		h.Set("MCP-Protocol-Version", version)
	}
	if session != "" {
		h.Set("Mcp-Session-Id", session)
	}
	return h
}

// do follows at most three redirects, never changes POST to GET, and never crosses
// hostnames or downgrades HTTPS. A response received before a redirect prevents fallback.
func (p *Prober) do(ctx context.Context, method, endpoint string, body []byte, h http.Header) (*http.Response, error, bool) {
	return p.exchange(ctx, method, endpoint, body, h, false)
}

// Legacy SSE's advertised POST channel stays on its origin even through redirects.
func (p *Prober) exchange(ctx context.Context, method, endpoint string, body []byte, h http.Header, sameOrigin bool) (*http.Response, error, bool) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err, false
	}
	initialHost := u.Hostname()
	initialScheme, initialAuthority := u.Scheme, u.Host
	hadResponse := false
	for redirects := 0; ; redirects++ {
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
		if err != nil {
			return nil, err, false
		}
		req.Header = h.Clone()
		r, err := p.client.Do(req)
		if err != nil {
			return nil, err, !hadResponse && ctx.Err() == nil
		}
		hadResponse = true
		if r.StatusCode < 300 || r.StatusCode > 399 || r.Header.Get("Location") == "" {
			return r, nil, false
		}
		next, err := r.Location()
		// Only 307/308 guarantee preservation of a POST body.
		allowedStatus := method == http.MethodGet || r.StatusCode == 307 || r.StatusCode == 308
		allowed := err == nil && next.User == nil && next.Fragment == "" && strings.EqualFold(next.Hostname(), initialHost) &&
			(next.Scheme == "http" || next.Scheme == "https") && !(u.Scheme == "https" && next.Scheme == "http")
		if allowed && sameOrigin {
			allowed = next.Scheme == initialScheme && strings.EqualFold(next.Host, initialAuthority)
		}
		if !allowedStatus || !allowed || redirects == 3 {
			r.Body.Close()
			return nil, fmt.Errorf("blocked or excessive redirect from %s", u.Redacted()), false
		}
		r.Body.Close()
		u = next
	}
}

type checkResult struct {
	index             int
	finding           *Finding
	err               error
	connectionFailure bool
}

func (p *Prober) probeURL(ctx, parent context.Context, endpoint string) ([]Finding, error, bool) {
	results := make(chan checkResult, 2)
	go func() {
		f, err, failed := p.streamableHTTP(ctx, parent, endpoint)
		results <- checkResult{0, f, err, failed}
	}()
	go func() {
		f, err, failed := p.legacySSE(ctx, parent, endpoint)
		results <- checkResult{1, f, err, failed}
	}()
	var checks [2]checkResult
	for range checks {
		r := <-results
		checks[r.index] = r
	}
	var findings []Finding
	byURL := make(map[string]int)
	for _, r := range checks {
		if r.finding == nil {
			continue
		}
		if i, ok := byURL[r.finding.URL]; ok {
			findings[i].Merge(*r.finding)
		} else {
			byURL[r.finding.URL] = len(findings)
			findings = append(findings, *r.finding)
		}
	}
	if len(findings) != 0 {
		// A failed or timed-out check cannot erase evidence from the other transport.
		return findings, nil, false
	}
	return nil, errors.Join(fmt.Errorf("%s unconfirmed: %w", StreamableHTTP, checks[0].err),
		fmt.Errorf("%s unconfirmed: %w", HTTPSSE, checks[1].err)), checks[0].connectionFailure && checks[1].connectionFailure
}

func (p *Prober) streamableHTTP(ctx, parent context.Context, endpoint string) (*Finding, error, bool) {
	r, err, failed := p.do(ctx, http.MethodPost, endpoint, requestBody("server/discover", modernVersion), headers("server/discover", modernVersion, ""))
	if err != nil {
		return nil, err, failed
	}
	endpoint = r.Request.URL.String()
	e, replyErr := readReply(r, "server/discover")
	r.Body.Close()
	if replyErr == nil && e.Error == nil && r.StatusCode >= 200 && r.StatusCode < 300 {
		f, err := discoveryResult(e.Result)
		if err == nil {
			f.URL = endpoint
			f.setResponseHeaders(r.Header)
			return f, nil, false
		}
	}
	if e.Error != nil && (e.Error.Code == -32020 || e.Error.Code == -32022) {
		// A modern protocol error must not be mistaken for legacy transport failure.
		if !hasLegacyVersion(e.Error.Data.Supported) {
			return nil, fmt.Errorf("modern MCP protocol error %d", e.Error.Code), false
		}
	}
	if r.StatusCode == 401 || r.StatusCode == 403 || r.StatusCode >= 500 {
		return nil, fmt.Errorf("unconfirmed endpoint: HTTP %d", r.StatusCode), false
	}
	f, _, err := p.initialize(ctx, parent, endpoint, nil)
	return f, err, false
}

func hasLegacyVersion(versions []string) bool {
	for _, v := range legacyVersions {
		if slices.Contains(versions, v) {
			return true
		}
	}
	return false
}

func discoveryResult(raw json.RawMessage) (*Finding, error) {
	var result struct {
		ResultType        string          `json:"resultType"`
		SupportedVersions []string        `json:"supportedVersions"`
		Capabilities      json.RawMessage `json:"capabilities"`
		Meta              struct {
			ServerInfo *ServerInfo `json:"io.modelcontextprotocol/serverInfo"`
		} `json:"_meta"`
	}
	if json.Unmarshal(raw, &result) != nil || result.ResultType != "complete" || len(result.SupportedVersions) == 0 || !object(result.Capabilities) {
		return nil, errors.New("invalid MCP discovery result")
	}
	for _, v := range result.SupportedVersions {
		if v == "" {
			return nil, errors.New("empty MCP protocol version")
		}
	}
	return newFinding("", StreamableHTTP, "server/discover", result.SupportedVersions, result.Meta.ServerInfo), nil
}

func initializeResult(raw json.RawMessage) (*Finding, error) {
	var result struct {
		ProtocolVersion string          `json:"protocolVersion"`
		Capabilities    json.RawMessage `json:"capabilities"`
		ServerInfo      *ServerInfo     `json:"serverInfo"`
	}
	if json.Unmarshal(raw, &result) != nil || !slices.Contains(legacyVersions, result.ProtocolVersion) || !object(result.Capabilities) ||
		result.ServerInfo == nil || result.ServerInfo.Name == "" || result.ServerInfo.Version == "" {
		return nil, errors.New("invalid or unsupported MCP initialize result")
	}
	return newFinding("", StreamableHTTP, "initialize", []string{result.ProtocolVersion}, result.ServerInfo), nil
}

func (p *Prober) initialize(ctx, parent context.Context, endpoint string, stream *events) (*Finding, int, error) {
	version := legacyVersions[0]
	if stream != nil {
		version = "2024-11-05"
	}
	// One version retry at most, and only to a version explicitly advertised by the server.
	for attempt := 0; attempt < 2; attempt++ {
		r, err, _ := p.exchange(ctx, http.MethodPost, endpoint, requestBody("initialize", version), headers("initialize", version, ""), stream != nil)
		if err != nil {
			return nil, 0, err
		}
		endpoint = r.Request.URL.String()
		status, session := r.StatusCode, r.Header.Get("Mcp-Session-Id")
		var e envelope
		if stream != nil && status == http.StatusAccepted {
			r.Body.Close()
			e, err = stream.reply("initialize")
		} else {
			e, err = readReply(r, "initialize")
			r.Body.Close()
		}
		if err != nil {
			return nil, status, err
		}
		if e.Error != nil {
			nextVersion := ""
			for _, v := range legacyVersions {
				if v != version && slices.Contains(e.Error.Data.Supported, v) {
					nextVersion = v
					break
				}
			}
			if nextVersion == "" || attempt == 1 {
				return nil, status, fmt.Errorf("initialize protocol error %d", e.Error.Code)
			}
			version = nextVersion
			continue
		}
		if status < 200 || status >= 300 {
			return nil, status, fmt.Errorf("initialize rejected: HTTP %d", status)
		}
		f, err := initializeResult(e.Result)
		if err != nil {
			return nil, status, err
		}
		f.URL = endpoint
		f.setResponseHeaders(r.Header)
		if session != "" {
			defer p.cleanup(parent, endpoint, f.ProtocolVersions[0], session, stream != nil)
		}
		p.initialized(ctx, endpoint, f.ProtocolVersions[0], session, stream != nil)
		return f, status, nil
	}
	return nil, 0, errors.New("no compatible initialize response")
}

func (p *Prober) initialized(ctx context.Context, endpoint, version, session string, sameOrigin bool) {
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	r, err, _ := p.exchange(ctx, http.MethodPost, endpoint, body, headers("notifications/initialized", version, session), sameOrigin)
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		r.Body.Close()
	}
}

func (p *Prober) cleanup(parent context.Context, endpoint, version, session string, sameOrigin bool) {
	ctx, cancel := context.WithTimeout(parent, 250*time.Millisecond)
	defer cancel()
	r, err, _ := p.exchange(ctx, http.MethodDelete, endpoint, nil, headers("", version, session), sameOrigin)
	if err == nil {
		r.Body.Close()
	}
}

func (p *Prober) legacySSE(ctx, parent context.Context, endpoint string) (*Finding, error, bool) {
	h := headers("", "", "")
	h.Set("Accept", "text/event-stream")
	r, err, failed := p.do(ctx, http.MethodGet, endpoint, nil, h)
	if err != nil {
		return nil, err, failed
	}
	defer r.Body.Close()
	if r.StatusCode != 200 || contentType(r) != "text/event-stream" {
		return nil, fmt.Errorf("not a legacy MCP event stream (HTTP %d)", r.StatusCode), false
	}
	stream := newEvents(r.Body)
	for {
		name, data, err := stream.next()
		if err != nil {
			return nil, err, false
		}
		if name != "endpoint" {
			continue
		}
		ref, err := url.Parse(string(data))
		if err != nil || ref.User != nil || ref.Fragment != "" {
			return nil, errors.New("invalid SSE POST endpoint"), false
		}
		postURL := r.Request.URL.ResolveReference(ref)
		if postURL.Scheme != r.Request.URL.Scheme || !strings.EqualFold(postURL.Host, r.Request.URL.Host) {
			return nil, errors.New("SSE POST endpoint is not on the same origin"), false
		}
		f, _, err := p.initialize(ctx, parent, postURL.String(), stream)
		if err != nil {
			return nil, err, false
		}
		legacy := newFinding(r.Request.URL.String(), HTTPSSE, f.Method, f.ProtocolVersions, f.ServerInfo)
		legacy.setResponseHeaders(r.Header)
		detail := legacy.TransportDetails[HTTPSSE]
		detail.PostEndpoint = f.URL
		detail.PostResponseHeaders = copyHeaders(f.TransportDetails[StreamableHTTP].ResponseHeaders)
		legacy.TransportDetails[HTTPSSE] = detail
		return legacy, nil, false
	}
}
