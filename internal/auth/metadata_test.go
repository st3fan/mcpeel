package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMetadataDiscovery(t *testing.T) {
	for _, mode := range []string{"linked", "endpoint", "root", "mismatch", "malformed", "oversized", "external", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			var base string
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "timeout" {
					<-r.Context().Done()
					return
				}
				if mode == "root" && strings.HasSuffix(r.URL.Path, "/mcp") {
					w.WriteHeader(404)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "malformed" {
					fmt.Fprint(w, `{broken`)
					return
				}
				if mode == "oversized" {
					fmt.Fprint(w, strings.Repeat(" ", maxMetadataBytes+1))
					return
				}
				resource := base + "/mcp"
				if mode == "mismatch" {
					resource += "/different"
				}
				fmt.Fprintf(w, `{"resource":%q,"authorization_servers":["https://issuer.example"],"scopes_supported":["read"],"bearer_methods_supported":["header"]}`, resource)
			}))
			defer s.Close()
			base = s.URL
			resolver := NewResolver(func(ctx context.Context, target string) (*http.Response, error) {
				req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
				return s.Client().Do(req)
			})
			r := &http.Response{StatusCode: 401, Request: httptest.NewRequest("POST", base+"/mcp", nil), Header: http.Header{}}
			header := "Bearer"
			if mode == "linked" {
				header += ` resource_metadata="` + base + `/metadata"`
			}
			if mode == "external" {
				header += ` resource_metadata="https://external.invalid/metadata"`
			}
			r.Header.Set("WWW-Authenticate", header)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			o := resolver.Enrich(ctx, Observe(r, "streamable-http", "server/discover"))
			if o.State != Required || len(o.Metadata) == 0 {
				t.Fatalf("missing evidence: %+v", o)
			}
			valid := mode == "linked" || mode == "endpoint" || mode == "root"
			if o.OAuthAdvertised != valid {
				t.Fatalf("OAuth classification: %+v", o)
			}
			if valid {
				last := o.Metadata[len(o.Metadata)-1]
				if last.Resource != base+"/mcp" || len(last.AuthorizationServers) != 1 || last.ScopesSupported[0] != "read" || last.BearerMethodsSupported[0] != "header" {
					t.Fatalf("metadata: %+v", last)
				}
			}
			if mode == "external" && (calls.Load() != 0 || o.Metadata[0].State != "external") {
				t.Fatalf("external URL fetched: %+v", o)
			}
			if mode == "root" && calls.Load() != 2 {
				t.Fatalf("root fallback requests=%d", calls.Load())
			}
		})
	}
}

func TestMetadataDeduplicationAndBudget(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(404)
	}))
	defer s.Close()
	resolver := NewResolver(func(ctx context.Context, target string) (*http.Response, error) {
		req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
		return s.Client().Do(req)
	})
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			o := Observation{URL: s.URL + "/mcp", HTTPStatus: 401, State: Required}
			resolver.Enrich(context.Background(), o)
		})
	}
	wg.Wait()
	if calls.Load() != 2 {
		t.Fatalf("metadata requests were not shared: %d", calls.Load())
	}
	for _, path := range []string{"a", "b", "c", "d"} {
		resolver.Enrich(context.Background(), Observation{URL: s.URL + "/" + path, HTTPStatus: 401})
	}
	if calls.Load() != 3 {
		t.Fatalf("metadata request budget exceeded: %d", calls.Load())
	}
}

func TestMetadataDiscoveryPreservesResourcePath(t *testing.T) {
	for _, suffix := range []string{"/", "/mcp/", "/mcp%2F", "/tenant%20one/mcp?version=1%2F2", "/mcp?"} {
		t.Run(suffix, func(t *testing.T) {
			var resource string
			var requests []string
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, r.RequestURI)
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"resource":%q}`, resource)
			}))
			defer s.Close()
			resource = s.URL + suffix
			resolver := NewResolver(func(ctx context.Context, target string) (*http.Response, error) {
				req, _ := http.NewRequestWithContext(ctx, "GET", target, nil)
				return s.Client().Do(req)
			})
			o := resolver.Enrich(context.Background(), Observation{URL: resource, HTTPStatus: 401})
			want := "/.well-known/oauth-protected-resource"
			if suffix != "/" {
				want += suffix
			}
			if !o.OAuthAdvertised || len(requests) != 1 || requests[0] != want || o.Metadata[0].Resource != resource {
				t.Fatalf("requests=%v want=%s observation=%+v", requests, want, o)
			}
		})
	}
}
