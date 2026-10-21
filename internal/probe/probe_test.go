package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/st3fan/mcpeel/internal/targets"
)

type rpcRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params struct {
		Version string `json:"protocolVersion"`
		Meta    struct {
			Version string `json:"io.modelcontextprotocol/protocolVersion"`
		} `json:"_meta"`
	} `json:"params"`
}

func probeOne(p *Prober, ctx context.Context, c targets.Candidate) (*Finding, error) {
	findings, err := p.Probe(ctx, c)
	if len(findings) == 0 {
		return nil, err
	}
	if len(findings) != 1 {
		return nil, fmt.Errorf("expected one endpoint, got %d", len(findings))
	}
	return &findings[0], err
}

func request(t *testing.T, r *http.Request) rpcRequest {
	t.Helper()
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Errorf("decode request: %v", err)
	}
	return req
}

func discovery() any {
	return map[string]any{"resultType": "complete", "supportedVersions": []string{modernVersion}, "capabilities": map[string]any{},
		"_meta": map[string]any{"io.modelcontextprotocol/serverInfo": ServerInfo{Name: "fixture", Version: "1"}}}
}

func initializedResult(version string) any {
	return map[string]any{"protocolVersion": version, "capabilities": map[string]any{}, "serverInfo": ServerInfo{Name: "fixture", Version: "1"}}
}

func reply(w http.ResponseWriter, id string, result any, stream bool) {
	data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	if stream {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		fmt.Fprintf(w, ": keepalive\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\r\n\r\ndata: %s\r\n\r\n", data)
	} else {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(data)
	}
}

func TestModernDiscovery(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(405)
					return
				}
				req := request(t, r)
				if req.Method != "server/discover" || req.Params.Meta.Version != modernVersion || r.Header.Get("Mcp-Method") != req.Method || r.Header.Get("MCP-Protocol-Version") != modernVersion ||
					!strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
					t.Errorf("invalid discovery request: %+v %v", req, r.Header)
				}
				reply(w, req.ID, discovery(), stream)
			}))
			defer s.Close()
			p := New(time.Second)
			defer p.Close()
			f, err := probeOne(p, context.Background(), targets.Candidate{Input: "original", URL: s.URL + "/mcp"})
			if err != nil || f == nil || f.URL != s.URL+"/mcp" || f.Method != "server/discover" || f.Input != "original" || f.ServerInfo.Name != "fixture" {
				t.Fatalf("finding = %+v, %v", f, err)
			}
		})
	}
}

func TestInitializeAndCleanup(t *testing.T) {
	for _, tt := range []struct {
		version string
		stream  bool
	}{
		{"2025-11-25", false}, {"2025-11-25", true},
		{"2025-06-18", false}, {"2025-06-18", true},
		{"2025-03-26", false}, {"2025-03-26", true},
		{"2024-11-05", false}, {"2024-11-05", true},
	} {
		t.Run(fmt.Sprintf("%s/stream=%v", tt.version, tt.stream), func(t *testing.T) {
			version := tt.version
			var notified, deleted atomic.Bool
			var attempts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(405)
					return
				}
				if r.Method == "DELETE" {
					deleted.Store(r.Header.Get("Mcp-Session-Id") == "session-1" && r.Header.Get("MCP-Protocol-Version") == version)
					w.WriteHeader(204)
					return
				}
				req := request(t, r)
				switch req.Method {
				case "server/discover":
					w.WriteHeader(400)
				case "initialize":
					attempts.Add(1)
					if req.Params.Version != version {
						w.Header().Set("Content-Type", "application/json")
						fmt.Fprintf(w, `{"jsonrpc":"2.0","id":"initialize","error":{"code":-32602,"data":{"supported":[%q]}}}`, version)
						return
					}
					w.Header().Set("Mcp-Session-Id", "session-1")
					reply(w, req.ID, initializedResult(version), tt.stream)
				case "notifications/initialized":
					notified.Store(r.Header.Get("Mcp-Session-Id") == "session-1" && r.Header.Get("MCP-Protocol-Version") == version)
					w.WriteHeader(202)
				default:
					t.Errorf("unexpected request: %+v", req)
				}
			}))
			defer s.Close()
			p := New(time.Second)
			defer p.Close()
			f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL})
			if err != nil || f == nil || f.ProtocolVersions[0] != version || !notified.Load() || !deleted.Load() {
				t.Fatalf("finding=%+v error=%v notified=%v deleted=%v", f, err, notified.Load(), deleted.Load())
			}
			want := int32(2)
			if version == legacyVersions[0] {
				want = 1
			}
			if attempts.Load() != want {
				t.Fatalf("initialize attempts=%d, want %d", attempts.Load(), want)
			}
		})
	}
}

func TestInvalidInitializeResult(t *testing.T) {
	for _, result := range []any{
		map[string]any{"protocolVersion": "2099-01-01", "capabilities": map[string]any{}, "serverInfo": ServerInfo{Name: "unknown", Version: "1"}},
		map[string]any{"protocolVersion": legacyVersions[0], "capabilities": nil, "serverInfo": ServerInfo{Name: "bad", Version: "1"}},
		map[string]any{"protocolVersion": legacyVersions[0], "capabilities": map[string]any{}},
		map[string]any{"protocolVersion": legacyVersions[0], "capabilities": map[string]any{}, "serverInfo": ServerInfo{Name: "missing version"}},
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				w.WriteHeader(405)
				return
			}
			req := request(t, r)
			if req.Method == "server/discover" {
				w.WriteHeader(400)
				return
			}
			reply(w, req.ID, result, false)
		}))
		p := New(time.Second)
		f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL})
		p.Close()
		s.Close()
		if f != nil || err == nil {
			t.Fatalf("accepted invalid initialize result %v: %+v, %v", result, f, err)
		}
	}
}

func TestLegacySSE(t *testing.T) {
	for _, endpoint := range []string{"messages?session=1", "/messages?session=1", "https://elsewhere.invalid/messages"} {
		t.Run(endpoint, func(t *testing.T) {
			responses := make(chan []byte, 1)
			closed := make(chan struct{})
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" && r.URL.Path == "/sse" {
					defer close(closed)
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
					w.(http.Flusher).Flush()
					select {
					case b := <-responses:
						fmt.Fprintf(w, "data: %s\n\n", b)
						w.(http.Flusher).Flush()
						<-r.Context().Done()
					case <-r.Context().Done():
					}
					return
				}
				if r.URL.Path != "/messages" {
					w.WriteHeader(405)
					return
				}
				req := request(t, r)
				if req.Method == "initialize" {
					if req.Params.Version != "2024-11-05" || r.URL.RawQuery != "session=1" {
						t.Errorf("wrong legacy request: %+v %s", req, r.URL)
					}
					b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": initializedResult("2024-11-05")})
					responses <- b
				}
				w.WriteHeader(202)
			}))
			defer s.Close()
			p := New(time.Second)
			defer p.Close()
			f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL + "/sse"})
			if strings.HasPrefix(endpoint, "https:") {
				if err == nil || f != nil {
					t.Fatalf("accepted cross-origin endpoint: %+v, %v", f, err)
				}
			} else if err != nil || f == nil || f.URL != s.URL+"/sse" || f.Transport != "http+sse" {
				t.Fatalf("finding = %+v, %v", f, err)
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("SSE connection not closed")
			}
		})
	}
}

func TestUnconfirmedResponses(t *testing.T) {
	for _, tt := range []struct {
		name, ct, body string
		status         int
	}{
		{"HTML", "text/html", "<html>MCP server</html>", 200},
		{"generic JSON", "application/json", `{"ok":true}`, 200},
		{"generic RPC", "application/json", `{"jsonrpc":"2.0","id":"server/discover","result":{}}`, 200},
		{"RPC error", "application/json", `{"jsonrpc":"2.0","id":"server/discover","error":{"code":-32601}}`, 200},
		{"wrong ID", "application/json", `{"jsonrpc":"2.0","id":"other","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`, 200},
		{"null capabilities", "application/json", `{"jsonrpc":"2.0","id":"server/discover","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":null}}`, 200},
		{"ambiguous RPC", "application/json", `{"jsonrpc":"2.0","id":"server/discover","result":{},"error":{"code":-1}}`, 200},
		{"auth", "text/plain", "Unauthorized", 401},
		{"forbidden", "text/plain", "Forbidden", 403},
		{"not found", "text/plain", "Not found", 404},
		{"unrelated SSE", "text/event-stream", "data: hello\n\n", 200},
		{"SSE endpoint only", "text/event-stream", "event: endpoint\ndata: /messages\n\n", 405},
		{"oversized JSON", "application/json", strings.Repeat(" ", maxResponseBytes+1), 200},
		{"oversized SSE", "text/event-stream", "data: " + strings.Repeat("x", maxResponseBytes+1) + "\n\n", 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.ct)
				w.WriteHeader(tt.status)
				io.WriteString(w, tt.body)
			}))
			defer s.Close()
			p := New(time.Second)
			defer p.Close()
			if f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL}); err == nil || f != nil {
				t.Fatalf("false confirmation: %+v, %v", f, err)
			}
		})
	}
}

func TestModernErrorDoesNotFallBack(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(405)
			return
		}
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		io.WriteString(w, `{"jsonrpc":"2.0","id":"server/discover","error":{"code":-32022,"data":{"supported":["2099-01-01"]}}}`)
	}))
	defer s.Close()
	p := New(time.Second)
	defer p.Close()
	if f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL}); f != nil || err == nil || calls.Load() != 1 {
		t.Fatalf("modern error fallback: %+v, %v, calls=%d", f, err, calls.Load())
	}
}

func TestFallback(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(405)
			return
		}
		req := request(t, r)
		reply(w, req.ID, discovery(), false)
	}))
	defer s.Close()
	p := New(time.Second)
	defer p.Close()
	secureURL := strings.Replace(s.URL, "http:", "https:", 1)
	if f, err := probeOne(p, context.Background(), targets.Candidate{URL: secureURL, Fallback: true}); err != nil || f == nil || f.URL != s.URL {
		t.Fatalf("schemeless fallback: %+v, %v", f, err)
	}
	if f, err := probeOne(p, context.Background(), targets.Candidate{URL: secureURL}); err == nil || f != nil {
		t.Fatalf("explicit HTTPS used fallback: %+v, %v", f, err)
	}
	var tlsCalls atomic.Int32
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsCalls.Add(1)
		w.WriteHeader(404)
	}))
	defer tlsServer.Close()
	p.client.Transport = tlsServer.Client().Transport
	if f, err := probeOne(p, context.Background(), targets.Candidate{URL: tlsServer.URL, Fallback: true}); err == nil || f != nil || tlsCalls.Load() != 3 {
		t.Fatalf("HTTP response caused fallback: %+v, %v, calls=%d", f, err, tlsCalls.Load())
	}
}

func TestRedirects(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(405)
					return
				}
				if r.URL.Path == "/" {
					w.Header().Set("Location", "/mcp")
					w.WriteHeader(status)
					return
				}
				if r.Method != "POST" {
					t.Errorf("redirect changed method to %s", r.Method)
				}
				req := request(t, r)
				reply(w, req.ID, discovery(), false)
			}))
			defer s.Close()
			p := New(time.Second)
			defer p.Close()
			f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL})
			if status == 307 || status == 308 {
				if err != nil || f == nil || f.URL != s.URL+"/mcp" {
					t.Fatalf("redirected finding = %+v, %v", f, err)
				}
			} else if err == nil || f != nil {
				t.Fatalf("followed non-preserving redirect: %+v, %v", f, err)
			}
		})
	}
	for _, location := range []string{"/", "https://different.invalid/mcp", "http://127.0.0.1:1/mcp"} {
		t.Run(location, func(t *testing.T) {
			var calls atomic.Int32
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					calls.Add(1)
				}
				w.Header().Set("Location", location)
				w.WriteHeader(307)
			}))
			defer s.Close()
			p := New(time.Second)
			p.client.Transport = s.Client().Transport
			defer p.Close()
			if f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL}); err == nil || f != nil || calls.Load() > 4 {
				t.Fatalf("unsafe/excess redirect: %+v, %v, calls=%d", f, err, calls.Load())
			}
		})
	}
}

func TestDeadlineAndCancellation(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, ": keepalive\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer s.Close()
	p := New(30 * time.Millisecond)
	defer p.Close()
	start := time.Now()
	if f, err := probeOne(p, context.Background(), targets.Candidate{URL: s.URL}); err == nil || f != nil || time.Since(start) > time.Second {
		t.Fatalf("deadline: %+v, %v after %s", f, err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f, err := probeOne(p, ctx, targets.Candidate{URL: s.URL, Fallback: true}); err == nil || f != nil {
		t.Fatalf("cancelled probe: %+v, %v", f, err)
	}
}

func TestEventParsing(t *testing.T) {
	for _, ending := range []string{"\n", "\r\n", "\r"} {
		body := strings.Join([]string{": comment", "event: message", "data: {\"jsonrpc\":\"2.0\",", "data: \"id\":\"test\",\"result\":{}}", "", ""}, ending)
		e, err := newEvents(strings.NewReader(body)).reply("test")
		if err != nil || !object(e.Result) {
			t.Fatalf("line ending %q: %+v, %v", ending, e, err)
		}
	}
}
