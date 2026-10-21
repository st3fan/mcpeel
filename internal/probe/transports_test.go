package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/st3fan/mcpeel/internal/targets"
)

type transportFixture struct {
	http, sse, streamedHTTP, initializeHTTP bool
	stallHTTP, stallSSE, badSSE, genericSSE bool
	crossOrigin, splitRedirects             bool
}

type transportState struct {
	closed  chan struct{}
	deleted atomic.Int32
}

func newTransportFixture(t *testing.T, cfg transportFixture) (*httptest.Server, *transportState) {
	t.Helper()
	state := &transportState{closed: make(chan struct{})}
	responses := make(chan []byte, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.splitRedirects && r.URL.Path == "/entry" {
			location := "/mcp"
			if r.Method == http.MethodGet {
				location = "/sse"
			}
			w.Header().Set("Location", location)
			w.WriteHeader(307)
			return
		}
		if r.Method == http.MethodDelete {
			wantSession := "http-session"
			if r.URL.Path == "/messages" {
				wantSession = "sse-session"
			}
			if r.Header.Get("Mcp-Session-Id") != wantSession {
				t.Errorf("wrong cleanup session: %v", r.Header)
			}
			state.deleted.Add(1)
			w.WriteHeader(204)
			return
		}
		if r.Method == http.MethodGet {
			if !cfg.sse && !cfg.stallSSE && !cfg.genericSSE {
				w.WriteHeader(405)
				return
			}
			defer close(state.closed)
			w.Header().Set("Content-Type", "text/event-stream")
			if cfg.stallSSE {
				fmt.Fprint(w, ": keepalive\n\n")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				return
			}
			if cfg.genericSSE {
				fmt.Fprint(w, "data: unrelated stream\n\n")
				return
			}
			endpoint := "/messages"
			if cfg.crossOrigin {
				endpoint = "https://elsewhere.invalid/messages"
			}
			fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
			w.(http.Flusher).Flush()
			select {
			case b := <-responses:
				fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			case <-r.Context().Done():
			}
			return
		}
		req := request(t, r)
		if req.Method == "notifications/initialized" {
			w.WriteHeader(202)
			return
		}
		if r.URL.Path == "/messages" {
			if req.Params.Version != "2024-11-05" {
				t.Errorf("legacy initialize version: %s", req.Params.Version)
			}
			result := map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
				"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "serverInfo": ServerInfo{Name: "sse-fixture", Version: "2"},
			}}
			if cfg.badSSE {
				delete(result, "result")
				result["error"] = map[string]any{"code": -32603}
			}
			b, _ := json.Marshal(result)
			responses <- b
			w.Header().Set("Mcp-Session-Id", "sse-session")
			w.WriteHeader(202)
			return
		}
		if cfg.stallHTTP {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, ": keepalive\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		if !cfg.http {
			w.WriteHeader(405)
			return
		}
		if cfg.initializeHTTP {
			if req.Method == "server/discover" {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Mcp-Session-Id", "http-session")
			reply(w, req.ID, initializedResult("2025-11-25"), cfg.streamedHTTP)
			return
		}
		reply(w, req.ID, discovery(), cfg.streamedHTTP)
	}))
	t.Cleanup(s.Close)
	return s, state
}

func TestSupportedTransports(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  transportFixture
		want []string
	}{
		{"HTTP JSON", transportFixture{http: true}, []string{StreamableHTTP}},
		{"HTTP streamed", transportFixture{http: true, streamedHTTP: true}, []string{StreamableHTTP}},
		{"legacy SSE", transportFixture{sse: true}, []string{HTTPSSE}},
		{"both", transportFixture{http: true, sse: true}, []string{StreamableHTTP, HTTPSSE}},
		{"both with sessions", transportFixture{http: true, sse: true, initializeHTTP: true}, []string{StreamableHTTP, HTTPSSE}},
		{"failed SSE initialization", transportFixture{http: true, sse: true, badSSE: true}, []string{StreamableHTTP}},
		{"generic SSE", transportFixture{http: true, genericSSE: true}, []string{StreamableHTTP}},
		{"cross-origin POST", transportFixture{http: true, sse: true, crossOrigin: true}, []string{StreamableHTTP}},
		{"stalled HTTP", transportFixture{stallHTTP: true, sse: true}, []string{HTTPSSE}},
		{"stalled SSE", transportFixture{http: true, stallSSE: true}, []string{StreamableHTTP}},
		{"both stalled", transportFixture{stallHTTP: true, stallSSE: true}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, state := newTransportFixture(t, tt.cfg)
			p := New(100 * time.Millisecond)
			defer p.Close()
			started := time.Now()
			findings, err := p.Probe(context.Background(), targets.Candidate{Input: "input", URL: s.URL + "/mcp"})
			if time.Since(started) > time.Second {
				t.Fatal("transport checks exceeded the shared budget")
			}
			if tt.want == nil {
				if len(findings) != 0 || err == nil {
					t.Fatalf("unexpected confirmation: %+v, %v", findings, err)
				}
				return
			}
			if err != nil || len(findings) != 1 {
				t.Fatalf("findings: %+v, %v", findings, err)
			}
			f := findings[0]
			if f.URL != s.URL+"/mcp" || f.Input != "input" || !reflect.DeepEqual(f.Transports, tt.want) || f.Transport != tt.want[0] || len(f.TransportDetails) != len(tt.want) {
				t.Fatalf("wrong transport support: %+v", f)
			}
			for _, transport := range tt.want {
				detail := f.TransportDetails[transport]
				version, name := modernVersion, "fixture"
				if transport == HTTPSSE {
					version, name = "2024-11-05", "sse-fixture"
				} else if tt.cfg.initializeHTTP {
					version = "2025-11-25"
				}
				if len(detail.ProtocolVersions) != 1 || detail.ProtocolVersions[0] != version || detail.ServerInfo == nil || detail.ServerInfo.Name != name {
					t.Fatalf("evidence mixed between transports: %+v", f)
				}
			}
			if tt.cfg.initializeHTTP && state.deleted.Load() != 2 {
				t.Fatalf("not all sessions cleaned up: %d", state.deleted.Load())
			}
			if tt.cfg.sse || tt.cfg.stallSSE || tt.cfg.genericSSE {
				select {
				case <-state.closed:
				case <-time.After(time.Second):
					t.Fatal("SSE stream was not closed")
				}
			}
		})
	}
}

func TestDifferentTransportRedirects(t *testing.T) {
	s, _ := newTransportFixture(t, transportFixture{http: true, sse: true, splitRedirects: true})
	p := New(time.Second)
	defer p.Close()
	findings, err := p.Probe(context.Background(), targets.Candidate{URL: s.URL + "/entry"})
	if err != nil || len(findings) != 2 || findings[0].URL != s.URL+"/mcp" || findings[1].URL != s.URL+"/sse" ||
		!reflect.DeepEqual(findings[0].Transports, []string{StreamableHTTP}) || !reflect.DeepEqual(findings[1].Transports, []string{HTTPSSE}) {
		t.Fatalf("different final URLs were combined: %+v, %v", findings, err)
	}
}

type deadlineTransport struct {
	http.RoundTripper
	mu        sync.Mutex
	deadlines []time.Time
}

func (d *deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	deadline, _ := r.Context().Deadline()
	d.mu.Lock()
	d.deadlines = append(d.deadlines, deadline)
	d.mu.Unlock()
	return d.RoundTripper.RoundTrip(r)
}

func TestTransportChecksShareDeadline(t *testing.T) {
	s, _ := newTransportFixture(t, transportFixture{http: true, stallSSE: true})
	p := New(50 * time.Millisecond)
	base := p.client.Transport.(*http.Transport)
	defer base.CloseIdleConnections()
	d := &deadlineTransport{RoundTripper: base}
	p.client.Transport = d
	findings, err := p.Probe(context.Background(), targets.Candidate{URL: s.URL + "/mcp"})
	d.mu.Lock()
	defer d.mu.Unlock()
	if err != nil || len(findings) != 1 || len(d.deadlines) != 2 || d.deadlines[0].IsZero() || !d.deadlines[0].Equal(d.deadlines[1]) {
		t.Fatalf("checks did not share a deadline: %+v, %v, deadlines=%v", findings, err, d.deadlines)
	}
}

func TestLegacyPostRedirectStaysOnOrigin(t *testing.T) {
	var outsideCalls atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outsideCalls.Add(1)
		w.WriteHeader(202)
	}))
	defer outside.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "event: endpoint\ndata: /messages\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		} else if r.URL.Path == "/messages" {
			w.Header().Set("Location", outside.URL+"/messages")
			w.WriteHeader(307)
		} else {
			w.WriteHeader(405)
		}
	}))
	defer s.Close()
	p := New(time.Second)
	defer p.Close()
	findings, err := p.Probe(context.Background(), targets.Candidate{URL: s.URL + "/mcp"})
	if err == nil || len(findings) != 0 || outsideCalls.Load() != 0 {
		t.Fatalf("legacy POST left its origin: %+v, %v, calls=%d", findings, err, outsideCalls.Load())
	}
}
