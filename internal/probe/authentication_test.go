package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/st3fan/mcpeel/internal/auth"
	"github.com/st3fan/mcpeel/internal/targets"
)

func TestAuthenticationEvidence(t *testing.T) {
	for _, tt := range []struct {
		name, challenge, state             string
		status                             int
		public, stallBody, stallGET, oauth bool
	}{
		{name: "basic", challenge: `Basic realm="private, zone"`, state: auth.Required, status: 401},
		{name: "digest", challenge: `Digest realm="private", nonce="abc"`, state: auth.Required, status: 401},
		{name: "bearer", challenge: `Bearer scope="read"`, state: auth.Required, status: 401},
		{name: "custom", challenge: `ApiKey realm="gateway"`, state: auth.Required, status: 401},
		{name: "bare 401", state: auth.Required, status: 401},
		{name: "bare 403", state: auth.Unknown, status: 403},
		{name: "scope denied", challenge: `Bearer error="insufficient_scope", scope="write"`, state: auth.Required, status: 403},
		{name: "public HTTP protected SSE", challenge: `Basic realm="sse"`, state: auth.Required, status: 401, public: true},
		{name: "401 stalled body", challenge: `Basic realm="body"`, state: auth.Required, status: 401, stallBody: true},
		{name: "OAuth with stalled other transport", challenge: `Bearer scope="read"`, state: auth.Required, status: 401, stallGET: true, oauth: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var base string
			var metadataCalls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/.well-known/") {
					metadataCalls.Add(1)
					if !tt.oauth {
						w.WriteHeader(404)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprintf(w, `{"resource":%q,"authorization_servers":["https://issuer.example"],"scopes_supported":["write"],"bearer_methods_supported":["header"]}`, base+"/mcp")
					return
				}
				if tt.public && r.Method == "POST" {
					req := request(t, r)
					reply(w, req.ID, discovery(), false)
					return
				}
				if tt.stallGET && r.Method == "GET" {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, ": keepalive\n\n")
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				if tt.challenge != "" {
					w.Header().Set("WWW-Authenticate", tt.challenge)
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Auth-Evidence", "preserved")
				w.WriteHeader(tt.status)
				if tt.stallBody {
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				fmt.Fprint(w, `{invalid body`)
			}))
			defer s.Close()
			base = s.URL
			p := New(200 * time.Millisecond)
			defer p.Close()
			start := time.Now()
			findings, err := p.Probe(context.Background(), targets.Candidate{Input: "input", URL: base + "/mcp"})
			if len(findings) != 1 || findings[0].MCPConfirmed != tt.public || tt.public && err != nil {
				t.Fatalf("incorrect confirmation: %+v, %v", findings, err)
			}
			f := findings[0]
			if !tt.public && (len(f.Transports) != 0 || f.ServerInfo != nil || f.Transport != "") {
				t.Fatalf("auth became MCP evidence: %+v", f)
			}
			if tt.stallBody && time.Since(start) > 150*time.Millisecond {
				t.Fatal("waited for challenged response body")
			}
			challenged, anonymous, metadata := false, false, false
			for _, o := range f.Authentication {
				if o.State == auth.AnonymousProbe {
					anonymous = true
					continue
				}
				if o.HTTPStatus != tt.status {
					continue
				}
				challenged = true
				if o.State != tt.state || o.URL != base+"/mcp" || o.ResponseHeaders.Get("X-Auth-Evidence") != "preserved" {
					t.Fatalf("lost challenge snapshot: %+v", o)
				}
				if tt.challenge != "" && (len(o.RawChallenges) != 1 || o.RawChallenges[0] != tt.challenge || len(o.Schemes) != 1) {
					t.Fatalf("scheme missing: %+v", o)
				}
				if o.OAuthAdvertised {
					metadata = true
					if !tt.oauth || o.Challenges[0].Parameters["scope"] != "read" || o.Metadata[0].ScopesSupported[0] != "write" {
						t.Fatalf("OAuth/scopes inferred incorrectly: %+v", o)
					}
				}
			}
			if !challenged || anonymous != tt.public || metadata != tt.oauth {
				t.Fatalf("missing independent observations: %+v", f)
			}
			if tt.oauth && metadataCalls.Load() != 1 {
				t.Fatalf("metadata fetched %d times", metadataCalls.Load())
			}
		})
	}
}

func TestLegacyAuthenticationStage(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: endpoint\ndata: /z-messages\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if r.URL.Path == "/z-messages" {
			w.Header().Set("WWW-Authenticate", `Basic realm="post"`)
			w.WriteHeader(401)
		} else {
			w.WriteHeader(405)
		}
	}))
	defer s.Close()
	p := New(time.Second)
	defer p.Close()
	findings, _ := p.Probe(context.Background(), targets.Candidate{URL: s.URL + "/sse"})
	if len(findings) != 1 || findings[0].URL != s.URL+"/sse" || findings[0].MCPConfirmed {
		t.Fatalf("legacy channel falsely confirmed: %+v", findings)
	}
	get, post := false, false
	for _, o := range findings[0].Authentication {
		if o.Transport != HTTPSSE {
			continue
		}
		get = get || o.Stage == "sse" && o.URL == s.URL+"/sse" && o.State == auth.Unknown
		post = post || o.Stage == "initialize" && o.URL == s.URL+"/z-messages" && o.State == auth.Required
	}
	if !get || !post {
		t.Fatalf("lost GET/POST policy: %+v", findings)
	}
}

func TestMetadataRedirectCannotLeaveOrigin(t *testing.T) {
	var outsideCalls atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outsideCalls.Add(1); w.WriteHeader(404) }))
	defer outside.Close()
	var base string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata" {
			w.Header().Set("Location", outside.URL)
			w.WriteHeader(307)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/metadata"`)
		w.WriteHeader(401)
	}))
	defer s.Close()
	base = s.URL
	p := New(time.Second)
	defer p.Close()
	findings, _ := p.Probe(context.Background(), targets.Candidate{URL: base + "/mcp"})
	if len(findings) != 1 || findings[0].MCPConfirmed || outsideCalls.Load() != 0 {
		t.Fatalf("metadata escaped origin: %+v, %d", findings, outsideCalls.Load())
	}
	for _, o := range findings[0].Authentication {
		if o.OAuthAdvertised || len(o.Metadata) != 1 || o.Metadata[0].State != "unavailable" {
			t.Fatalf("invalid metadata accepted: %+v", o)
		}
	}
}
