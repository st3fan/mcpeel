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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
					if err := json.Unmarshal([]byte(line), &f); err != nil || want[f.URL] == "" || f.Input != want[f.URL] || f.Method != "server/discover" || f.Transport != "streamable-http" {
						t.Fatalf("JSONL finding: %s, %v", line, err)
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

type checkFunc func(context.Context, targets.Candidate) (*probe.Finding, error)

func (f checkFunc) Probe(ctx context.Context, c targets.Candidate) (*probe.Finding, error) {
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
	p := checkFunc(func(ctx context.Context, c targets.Candidate) (*probe.Finding, error) {
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
		return &probe.Finding{URL: "https://found.invalid/mcp"}, nil
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
	p := checkFunc(func(ctx context.Context, c targets.Candidate) (*probe.Finding, error) {
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
	p = checkFunc(func(ctx context.Context, c targets.Candidate) (*probe.Finding, error) {
		return &probe.Finding{URL: c.URL}, nil
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
