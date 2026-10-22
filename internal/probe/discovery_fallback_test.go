package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/st3fan/mcpeel/internal/auth"
	"github.com/st3fan/mcpeel/internal/targets"
)

func TestDiscovery5xxInitialization(t *testing.T) {
	const valid = `{"jsonrpc":"2.0","id":"initialize","result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`
	for _, tt := range []struct {
		name, discoveryBody, initializeBody string
		discoveryStatus, initializeStatus   int
		confirmed                           bool
	}{
		{"empty 500", "", valid, 500, 200, true},
		{"HTML 500", "<html>Internal error</html>", valid, 500, 200, true},
		{"HTML 503", "<html>Unavailable</html>", valid, 503, 200, true},
		{"generic HTML", "", "<html>MCP server</html>", 500, 200, false},
		{"failed initialize", "", valid, 500, 500, false},
		{"wrong ID", "", `{"jsonrpc":"2.0","id":"other","result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`, 500, 200, false},
		{"invalid MCP result", "", `{"jsonrpc":"2.0","id":"initialize","result":{}}`, 500, 200, false},
		{"session error", "", `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Session ID required"}}`, 500, 400, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var attempts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Session ID required"}}`)
					return
				}
				req := request(t, r)
				switch req.Method {
				case "server/discover":
					w.Header().Set("Content-Type", "text/html")
					w.Header().Set("X-Phase", "discovery-error")
					w.WriteHeader(tt.discoveryStatus)
					fmt.Fprint(w, tt.discoveryBody)
				case "initialize":
					attempts.Add(1)
					w.Header().Set("X-Phase", "initialize")
					w.WriteHeader(tt.initializeStatus)
					fmt.Fprint(w, tt.initializeBody)
				case "notifications/initialized":
					w.WriteHeader(202)
				default:
					t.Errorf("unexpected request: %+v", req)
				}
			}))
			defer s.Close()
			p := New(time.Second)
			defer p.Close()
			findings, err := p.Probe(context.Background(), targets.Candidate{URL: s.URL + "/mcp"})
			if attempts.Load() != 1 {
				t.Fatalf("initialize attempts=%d, want 1; findings=%+v error=%v", attempts.Load(), findings, err)
			}
			if !tt.confirmed {
				if len(findings) != 0 || err == nil {
					t.Fatalf("false MCP confirmation: %+v, %v", findings, err)
				}
				return
			}
			if err != nil || len(findings) != 1 {
				t.Fatalf("missing initialization finding: %+v, %v", findings, err)
			}
			f := findings[0]
			if !f.MCPConfirmed || f.URL != s.URL+"/mcp" || len(f.Transports) != 1 || f.Transport != StreamableHTTP || f.Method != "initialize" ||
				len(f.ProtocolVersions) != 1 || f.ProtocolVersions[0] != "2025-03-26" || f.ServerInfo == nil || *f.ServerInfo != (ServerInfo{Name: "fixture", Version: "1"}) ||
				f.TransportDetails[StreamableHTTP].ResponseHeaders.Get("X-Phase") != "initialize" {
				t.Fatalf("incorrect confirmation evidence: %+v", f)
			}
			discovery, anonymous, sessionError := false, false, false
			for _, o := range f.Authentication {
				discovery = discovery || o.Stage == "server/discover" && o.HTTPStatus == tt.discoveryStatus && o.State == auth.Unknown && o.Error != "" && o.ResponseHeaders.Get("X-Phase") == "discovery-error"
				anonymous = anonymous || o.Stage == "initialize" && o.HTTPStatus == 200 && o.State == auth.AnonymousProbe
				sessionError = sessionError || o.Stage == "sse" && o.HTTPStatus == 400 && o.State == auth.Unknown
			}
			if !discovery || !anonymous || !sessionError {
				t.Fatalf("lost per-stage evidence: %+v", f.Authentication)
			}
		})
	}
}

func TestDiscoveryAuthDoesNotInitialize(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var posts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					w.WriteHeader(405)
					return
				}
				posts.Add(1)
				req := request(t, r)
				if req.Method != "server/discover" {
					t.Errorf("unexpected fallback: %s", req.Method)
				}
				w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
				w.WriteHeader(status)
			}))
			defer s.Close()
			p := New(time.Second)
			defer p.Close()
			findings, err := p.Probe(context.Background(), targets.Candidate{URL: s.URL})
			if err == nil || posts.Load() != 1 || len(findings) != 1 || findings[0].MCPConfirmed || len(findings[0].Transports) != 0 {
				t.Fatalf("auth response changed fallback/confirmation: %+v, %v, posts=%d", findings, err, posts.Load())
			}
		})
	}
}

func TestDiscovery5xxInitializationSharesDeadline(t *testing.T) {
	var attempts atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(405)
			return
		}
		req := request(t, r)
		if req.Method == "server/discover" {
			w.WriteHeader(500)
			return
		}
		attempts.Add(1)
		<-r.Context().Done()
	}))
	defer s.Close()
	p := New(100 * time.Millisecond)
	base := p.client.Transport.(*http.Transport)
	defer base.CloseIdleConnections()
	d := &deadlineTransport{RoundTripper: base}
	p.client.Transport = d
	findings, err := p.Probe(context.Background(), targets.Candidate{URL: s.URL})
	d.mu.Lock()
	defer d.mu.Unlock()
	if err == nil || len(findings) != 0 || attempts.Load() != 1 || len(d.deadlines) != 3 {
		t.Fatalf("deadline fallback: %+v, %v, attempts=%d deadlines=%v", findings, err, attempts.Load(), d.deadlines)
	}
	for _, deadline := range d.deadlines {
		if deadline.IsZero() || !deadline.Equal(d.deadlines[0]) {
			t.Fatalf("fallback reset the endpoint deadline: %v", d.deadlines)
		}
	}
}
