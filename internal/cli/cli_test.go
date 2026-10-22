package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/st3fan/mcpeel/internal/auth"
	"github.com/st3fan/mcpeel/internal/probe"
	"github.com/st3fan/mcpeel/internal/targets"
)

func TestCommandInputsAndOutput(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "/mcp")
			w.WriteHeader(307)
			return
		}
		if r.URL.Path != "/mcp" && r.URL.Path != "/other-mcp" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Endpoint", r.URL.Path)
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"server/discover","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`)
	}))
	defer s.Close()
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("# hosts\n"+s.URL+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		args  []string
		stdin string
	}{
		{"stdin", nil, s.URL + "\n"},
		{"file", []string{"-l", path}, ""},
		{"file alias", []string{"-list", path}, ""},
		{"target", []string{"-u", s.URL, "-target", s.URL + "/mcp"}, ""},
		{"millisecond timeout", []string{"-u", s.URL, "-timeout", "750ms"}, ""},
		{"fractional timeout", []string{"-u", s.URL, "-timeout", "2.5s"}, ""},
		{"longer timeout", []string{"-u", s.URL, "-timeout", "10s"}, ""},
		{"explicit stdin", []string{"-l", "-"}, s.URL},
		{"combined", []string{"-list", path, "-u", s.URL}, s.URL + "/mcp"},
		{"invalid mixed", []string{"-u", "ftp://invalid", "-u", s.URL}, "bad host\n"},
		{"JSONL/-json", []string{"-u", s.URL, "-u", s.URL + "/other-mcp", "-json", "-v"}, ""},
		{"JSONL/-j", []string{"-u", s.URL, "-u", s.URL + "/other-mcp", "-j", "-v"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := Run(context.Background(), tt.args, strings.NewReader(tt.stdin), &out, &errOut)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, &errOut)
			}
			if strings.HasPrefix(tt.name, "JSONL/") {
				lines := strings.Split(out.String(), "\n")
				if len(lines) != 3 || lines[2] != "" {
					t.Fatalf("expected two newline-terminated JSON objects, got %q", &out)
				}
				want := map[string]string{s.URL + "/mcp": s.URL, s.URL + "/other-mcp": s.URL + "/other-mcp"}
				for _, line := range lines[:2] {
					var f probe.Finding
					if err := json.Unmarshal([]byte(line), &f); err != nil || want[f.URL] == "" || f.Input != want[f.URL] || f.Method != "server/discover" || f.Transport != "streamable-http" || !reflect.DeepEqual(f.Transports, []string{probe.StreamableHTTP}) {
						t.Fatalf("JSONL finding: %s, %v", line, err)
					}
					headers := f.TransportDetails[probe.StreamableHTTP].ResponseHeaders
					if headers.Get("X-Endpoint") != strings.TrimPrefix(f.URL, s.URL) || !reflect.DeepEqual(headers.Values("Set-Cookie"), []string{"a=1; Path=/", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"}) {
						t.Fatalf("JSONL lost endpoint response headers: %s", line)
					}
					delete(want, f.URL)
				}
				if errOut.Len() == 0 {
					t.Fatal("verbose mode omitted unconfirmed diagnostics")
				}
			} else if out.String() != s.URL+"/mcp\n" {
				t.Fatalf("expected one confirmed URL, got %q", &out)
			}
			if tt.name == "invalid mixed" && !strings.Contains(errOut.String(), "invalid target") {
				t.Fatal("missing invalid input diagnostics")
			}
		})
	}
}

func TestLoadDedupAndFallback(t *testing.T) {
	cfg := config{targets: stringsFlag{"https://example.com/mcp", "example.com"}}
	cs, diagnostics, err := load(context.Background(), cfg, strings.NewReader("example.com\nhttps://example.com/mcp\n"))
	if err != nil || len(diagnostics) != 0 || len(cs) != 10 {
		t.Fatalf("load = %v, %v, %v", cs, diagnostics, err)
	}
	for _, c := range cs {
		if !c.Fallback || c.Input != "example.com" {
			t.Fatalf("fallback must be attributed to schemeless input: %+v", c)
		}
	}
	cfg.noSubdomain = true
	cs, _, _ = load(context.Background(), cfg, strings.NewReader(""))
	if len(cs) != 5 {
		t.Fatalf("disabled expansion: %v", cs)
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestCommandFailures(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		in   io.Reader
		code int
	}{
		{"help", []string{"-h"}, strings.NewReader(""), 0},
		{"no input", nil, strings.NewReader(""), 1},
		{"invalid only", []string{"-u", "bad host"}, strings.NewReader(""), 1},
		{"bad concurrency", []string{"-c", "0"}, strings.NewReader(""), 2},
		{"bad timeout", []string{"-timeout", "0s"}, strings.NewReader(""), 2},
		{"negative timeout", []string{"-timeout", "-1s"}, strings.NewReader(""), 2},
		{"invalid timeout", []string{"-timeout", "oops"}, strings.NewReader(""), 2},
		{"bad flag", []string{"-wat"}, strings.NewReader(""), 2},
		{"positional", []string{"example.com"}, strings.NewReader(""), 2},
		{"missing file", []string{"-l", filepath.Join(t.TempDir(), "missing")}, strings.NewReader(""), 1},
		{"read failure", nil, brokenReader{}, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := Run(context.Background(), tt.args, tt.in, &out, &errOut); code != tt.code || out.Len() != 0 || errOut.Len() == 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, &out, &errOut)
			}
			if tt.name == "help" && !strings.Contains(errOut.String(), "(default 2.5s)") {
				t.Fatalf("help omitted the 2.5s default: %s", &errOut)
			}
		})
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), nil, devNull, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "Usage:") {
		t.Fatalf("no interactive input: exit %d, %s", code, &errOut)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code := Run(ctx, []string{"-u", "example.com"}, strings.NewReader(""), &out, &errOut); code != 130 {
		t.Fatalf("cancelled command: exit %d", code)
	}
}

type checkFunc func(context.Context, targets.Candidate) ([]probe.Finding, error)

func (f checkFunc) Probe(ctx context.Context, c targets.Candidate) ([]probe.Finding, error) {
	return f(ctx, c)
}

func testCandidates(n int) []targets.Candidate {
	cs := make([]targets.Candidate, n)
	for i := range cs {
		cs[i].URL = fmt.Sprintf("https://host%d.invalid/mcp", i)
	}
	return cs
}

func TestWorkerBoundAndFindingDedup(t *testing.T) {
	var active, peak, count atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	p := checkFunc(func(ctx context.Context, c targets.Candidate) ([]probe.Finding, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		if n == 3 {
			once.Do(func() { close(release) })
		}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		count.Add(1)
		return []probe.Finding{{URL: "https://found.invalid/mcp", MCPConfirmed: true}}, nil
	})
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := scan(ctx, config{concurrency: 3}, testCandidates(20), p, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if peak.Load() != 3 || count.Load() != 20 || out.String() != "https://found.invalid/mcp\n" {
		t.Fatalf("peak=%d count=%d output=%q", peak.Load(), count.Load(), &out)
	}
}

func TestScanCancellationAndOutputFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	var once sync.Once
	p := checkFunc(func(ctx context.Context, c targets.Candidate) ([]probe.Finding, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	done := make(chan error, 1)
	go func() { done <- scan(ctx, config{concurrency: 2}, testCandidates(100), p, io.Discard, io.Discard) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("workers failed to stop on cancellation")
	}
	p = checkFunc(func(ctx context.Context, c targets.Candidate) ([]probe.Finding, error) {
		return []probe.Finding{{URL: c.URL, MCPConfirmed: true}}, nil
	})
	if err := scan(context.Background(), config{concurrency: 2}, testCandidates(100), p, brokenWriter{}, io.Discard); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("output failure: %v", err)
	}
}

func TestNoFindingsIsSuccess(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	var out, errOut bytes.Buffer
	if code := Run(context.Background(), []string{"-u", s.URL}, strings.NewReader(""), &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("zero findings: code=%d stdout=%q stderr=%q", code, &out, &errOut)
	}
}

func TestCommandTimeoutContinuesToOtherEndpoints(t *testing.T) {
	canceled := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			if r.Method == http.MethodGet {
				w.WriteHeader(405)
				return
			}
			var req struct{ Method string }
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode request: %v", err)
				return
			}
			if req.Method == "server/discover" {
				w.WriteHeader(400)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, ": keepalive\n\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(canceled)
		case "/mcp":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":"server/discover","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer s.Close()
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"-u", s.URL + "/slow", "-timeout", "30ms", "-c", "1", "-v"}, strings.NewReader(""), &out, &errOut)
	if code != 0 || out.String() != s.URL+"/mcp\n" || !strings.Contains(errOut.String(), "context deadline exceeded") {
		t.Fatalf("timed-out target interrupted scan: code=%d stdout=%q stderr=%q", code, &out, &errOut)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("stalled initialize stream was not canceled")
	}
}

func TestScanCombinesTransportEvidence(t *testing.T) {
	const endpoint = "https://found.invalid/mcp"
	cs := testCandidates(3)
	p := checkFunc(func(ctx context.Context, c targets.Candidate) ([]probe.Finding, error) {
		transport, method, version, name := probe.StreamableHTTP, "server/discover", "2026-07-28", "http-fixture"
		if c.URL == cs[0].URL {
			transport, method, version, name = probe.HTTPSSE, "initialize", "2024-11-05", "sse-fixture"
		} else if c.URL == cs[2].URL {
			method, version, name = "initialize", "2025-11-25", "older-http-fixture"
		}
		info := &probe.ServerInfo{Name: name, Version: "1"}
		versions := []string{version}
		detail := probe.TransportEvidence{
			Method: method, ProtocolVersions: versions, ServerInfo: info,
			ResponseHeaders: http.Header{"X-Fixture": {name}, "Set-Cookie": {name + "-a=1", name + "-b=2"}},
		}
		if transport == probe.HTTPSSE {
			detail.PostEndpoint = "https://found.invalid/messages"
			detail.PostResponseHeaders = http.Header{"X-Fixture": {"sse-post"}}
		}
		return []probe.Finding{{
			Input: c.URL, URL: endpoint, Transports: []string{transport}, MCPConfirmed: true,
			TransportDetails: map[string]probe.TransportEvidence{transport: detail},
			Transport:        transport, Method: method, ProtocolVersions: versions, ServerInfo: info,
		}}, nil
	})
	for _, order := range [][]targets.Candidate{cs, {cs[2], cs[1], cs[0]}} {
		for _, workers := range []int{1, 3} {
			for _, structured := range []bool{false, true} {
				t.Run(fmt.Sprintf("first=%s/workers=%d/json=%v", order[0].URL, workers, structured), func(t *testing.T) {
					var out bytes.Buffer
					if err := scan(context.Background(), config{concurrency: workers, json: structured}, order, p, &out, io.Discard); err != nil {
						t.Fatal(err)
					}
					if !structured {
						if out.String() != endpoint+"\n" {
							t.Fatalf("plain output duplicated endpoint: %q", &out)
						}
						return
					}
					var f probe.Finding
					if err := json.Unmarshal(out.Bytes(), &f); err != nil {
						t.Fatalf("expected one combined JSON record: %s, %v", &out, err)
					}
					if f.URL != endpoint || !reflect.DeepEqual(f.Transports, []string{probe.StreamableHTTP, probe.HTTPSSE}) || len(f.TransportDetails) != 2 || f.Transport != probe.StreamableHTTP {
						t.Fatalf("lost transport evidence while deduplicating: %+v", f)
					}
					httpDetail, sseDetail := f.TransportDetails[probe.StreamableHTTP], f.TransportDetails[probe.HTTPSSE]
					if httpDetail.Method != "server/discover" || httpDetail.ServerInfo.Name != "http-fixture" || !reflect.DeepEqual(httpDetail.ProtocolVersions, []string{"2026-07-28", "2025-11-25"}) ||
						sseDetail.ServerInfo.Name != "sse-fixture" || !reflect.DeepEqual(sseDetail.ProtocolVersions, []string{"2024-11-05"}) || !reflect.DeepEqual(f.ProtocolVersions, httpDetail.ProtocolVersions) || f.Method != httpDetail.Method || f.ServerInfo.Name != httpDetail.ServerInfo.Name {
						t.Fatalf("combined metadata is inconsistent: %+v", f)
					}
					if httpDetail.ResponseHeaders.Get("X-Fixture") != "http-fixture" || sseDetail.ResponseHeaders.Get("X-Fixture") != "sse-fixture" ||
						!reflect.DeepEqual(httpDetail.ResponseHeaders.Values("Set-Cookie"), []string{"http-fixture-a=1", "http-fixture-b=2"}) ||
						sseDetail.PostEndpoint != "https://found.invalid/messages" || sseDetail.PostResponseHeaders.Get("X-Fixture") != "sse-post" {
						t.Fatalf("deduplication mixed response headers: %+v", f)
					}
				})
			}
		}
	}
}

func TestAuthenticationOutput(t *testing.T) {
	for _, public := range []bool{false, true} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/mcp" {
				w.WriteHeader(404)
				return
			}
			if public && r.Method == "POST" {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":"server/discover","result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="private"`)
			w.WriteHeader(401)
		}))
		for _, flag := range []string{"", "-j", "-json"} {
			var out, errOut bytes.Buffer
			args := []string{"-u", s.URL + "/mcp"}
			if flag != "" {
				args = append(args, flag)
			}
			code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut)
			if code != 0 || errOut.Len() != 0 {
				t.Fatalf("scan failed: %d %s", code, &errOut)
			}
			if flag == "" {
				want := ""
				if public {
					want = s.URL + "/mcp\n"
				}
				if out.String() != want {
					t.Fatalf("plain output included unconfirmed endpoint: %q", &out)
				}
				continue
			}
			var f probe.Finding
			if err := json.Unmarshal(out.Bytes(), &f); err != nil || f.MCPConfirmed != public || len(f.Authentication) != 2 || !public && len(f.Transports) != 0 {
				t.Fatalf("JSONL confirmation/auth mismatch: %s, %v", &out, err)
			}
			anonymous, required := false, false
			for _, o := range f.Authentication {
				anonymous = anonymous || o.State == auth.AnonymousProbe
				required = required || o.State == auth.Required && len(o.Schemes) == 1 && o.Schemes[0] == "Basic"
			}
			if anonymous != public || !required {
				t.Fatalf("lost mixed access observations: %+v", f)
			}
		}
		s.Close()
	}
}

func TestDiscovery5xxOutput(t *testing.T) {
	for _, requireAuth := range []bool{false, true} {
		t.Run(fmt.Sprintf("auth=%v", requireAuth), func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/mcp" {
					w.WriteHeader(404)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					w.WriteHeader(400)
					fmt.Fprint(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":"Session ID required"}}`)
					return
				}
				var req struct{ Method string }
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("decode request: %v", err)
				}
				switch req.Method {
				case "server/discover":
					w.WriteHeader(500)
				case "initialize":
					if requireAuth {
						w.Header().Set("WWW-Authenticate", `Basic realm="initialize"`)
						w.WriteHeader(401)
						return
					}
					fmt.Fprint(w, `{"jsonrpc":"2.0","id":"initialize","result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"fixture","version":"1"}}}`)
				case "notifications/initialized":
					w.WriteHeader(202)
				default:
					t.Errorf("unexpected request: %s", req.Method)
				}
			}))
			defer s.Close()
			for _, flag := range []string{"", "-j", "-json"} {
				var out, errOut bytes.Buffer
				args := []string{"-u", s.URL + "/mcp", "-no-subdomain"}
				if flag != "" {
					args = append(args, flag)
				}
				if code := Run(context.Background(), args, strings.NewReader(""), &out, &errOut); code != 0 || errOut.Len() != 0 {
					t.Fatalf("scan failed: %d %s", code, &errOut)
				}
				if flag == "" {
					want := ""
					if !requireAuth {
						want = s.URL + "/mcp\n"
					}
					if out.String() != want {
						t.Fatalf("plain output=%q want=%q", &out, want)
					}
					continue
				}
				var f probe.Finding
				if err := json.Unmarshal(out.Bytes(), &f); err != nil || f.MCPConfirmed != !requireAuth || len(f.Authentication) != 3 {
					t.Fatalf("JSONL lost fallback evidence: %s, %v", &out, err)
				}
				if requireAuth {
					if len(f.Transports) != 0 || f.ServerInfo != nil {
						t.Fatalf("auth became confirmation: %+v", f)
					}
				} else if f.Method != "initialize" || f.ServerInfo == nil || f.ServerInfo.Name != "fixture" || !reflect.DeepEqual(f.Transports, []string{probe.StreamableHTTP}) {
					t.Fatalf("incorrect initialization evidence: %+v", f)
				}
				found := false
				for _, o := range f.Authentication {
					if o.Stage == "initialize" {
						found = o.State == auth.AnonymousProbe && !requireAuth || o.State == auth.Required && requireAuth && reflect.DeepEqual(o.Schemes, []string{"Basic"})
					}
				}
				if !found {
					t.Fatalf("lost initialization access state: %+v", f.Authentication)
				}
			}
		})
	}
}

func TestMergeAuthenticationWithConfirmedAliases(t *testing.T) {
	cs := testCandidates(3)
	const endpoint = "https://found.invalid/mcp"
	p := checkFunc(func(ctx context.Context, c targets.Candidate) ([]probe.Finding, error) {
		o := auth.Observation{URL: endpoint, Transport: probe.HTTPSSE, Stage: "sse", Method: "GET", State: auth.Required, HTTPStatus: 401, Schemes: []string{"Basic"}}
		f := probe.Finding{URL: endpoint, Transports: []string{}, TransportDetails: map[string]probe.TransportEvidence{}, Authentication: []auth.Observation{o}}
		if c.URL == cs[1].URL {
			f.MCPConfirmed = true
			f.Transports = []string{probe.StreamableHTTP}
			f.TransportDetails[probe.StreamableHTTP] = probe.TransportEvidence{Method: "server/discover", ProtocolVersions: []string{"2026-07-28"}}
			f.Authentication = []auth.Observation{{URL: endpoint, Transport: probe.StreamableHTTP, Stage: "server/discover", Method: "POST", State: auth.AnonymousProbe, HTTPStatus: 200}}
		}
		return []probe.Finding{f}, nil
	})
	for _, order := range [][]targets.Candidate{cs, {cs[1], cs[0], cs[2]}} {
		for _, structured := range []bool{false, true} {
			var out bytes.Buffer
			if err := scan(context.Background(), config{concurrency: 1, json: structured}, order, p, &out, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !structured {
				if out.String() != endpoint+"\n" {
					t.Fatalf("alias hid confirmed URL: %q", &out)
				}
				continue
			}
			var f probe.Finding
			if err := json.Unmarshal(out.Bytes(), &f); err != nil || !f.MCPConfirmed || len(f.Transports) != 1 || len(f.Authentication) != 2 {
				t.Fatalf("lost/doubled merged auth evidence: %s, %v", &out, err)
			}
		}
	}
}
