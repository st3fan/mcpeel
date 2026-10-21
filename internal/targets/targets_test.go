package targets

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for _, tt := range []struct {
		input, want string
		auto        bool
	}{
		{" example.com ", "https://example.com/", true},
		{"EXAMPLE.com.:8443/mcp?key=1", "https://example.com:8443/mcp?key=1", true},
		{"HTTP://Example.com/a%2Fb?q=x%2Fy", "http://example.com/a%2Fb?q=x%2Fy", false},
		{"https://example.com/?", "https://example.com/?", false},
		{"127.0.0.1:8000", "https://127.0.0.1:8000/", true},
		{"[::1]:8000/mcp", "https://[::1]:8000/mcp", true},
		{"https://[2001:db8::1]/", "https://[2001:db8::1]/", false},
		{"localhost", "https://localhost/", true},
	} {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if err != nil || got.URL.String() != tt.want || got.AutoScheme != tt.auto {
				t.Fatalf("Parse = %+v, %v; want %s, auto=%v", got, err, tt.want, tt.auto)
			}
		})
	}
	for _, input := range []string{"", "https://", "ftp://example.com", "https://user:pass@example.com", "example.com/#x", "example.com/#", "bad host", "example..com", "-bad.com", "example.com:0", "example.com:65536", "example.com:", "example.com:no", "::1", "2001:db8::1", "[example.com]", "https://example.com/\nfoo", "https:///mcp"} {
		t.Run(input, func(t *testing.T) {
			if got, err := Parse(input); err == nil {
				t.Fatalf("accepted invalid input %q: %+v", input, got)
			}
		})
	}
}

func TestCandidates(t *testing.T) {
	target, err := Parse("https://api.example.com:8443/custom%2Fmcp?x=1")
	if err != nil {
		t.Fatal(err)
	}
	got := Candidates(target, true)
	var urls []string
	for _, c := range got {
		urls = append(urls, c.URL)
		if c.Input != target.Input || c.Fallback {
			t.Fatalf("lost input or explicit scheme: %+v", c)
		}
	}
	want := []string{"https://api.example.com:8443/custom%2Fmcp?x=1"}
	for _, host := range []string{"api.example.com", "mcp.api.example.com"} {
		for _, path := range []string{"/", "/mcp", "/sse", "/mcp/sse", "/api/mcp"} {
			want = append(want, "https://"+host+":8443"+path)
		}
	}
	if !reflect.DeepEqual(urls, want) {
		t.Fatalf("candidates = %v; want %v", urls, want)
	}
	for _, input := range []string{"127.0.0.1", "[::1]:8000", "localhost", "service.localhost", "mcp.example.com"} {
		target, err := Parse(input + "/mcp")
		if err != nil {
			t.Fatal(err)
		}
		cs := Candidates(target, true)
		if len(cs) != 5 || !cs[0].Fallback {
			t.Fatalf("%s: expected five unique candidates without expansion: %v", input, cs)
		}
	}
	target, _ = Parse("example.com")
	if cs := Candidates(target, false); len(cs) != 5 {
		t.Fatalf("disabled expansion: %v", cs)
	}
}

func TestReadLines(t *testing.T) {
	var lines []string
	err := ReadLines(strings.NewReader(" # comment\r\n\n example.com \r\nhttps://example.net/mcp\n"), func(s string) error {
		lines = append(lines, s)
		return nil
	})
	if err != nil || !reflect.DeepEqual(lines, []string{"example.com", "https://example.net/mcp"}) {
		t.Fatalf("ReadLines = %v, %v", lines, err)
	}
	wantErr := errors.New("stop")
	if err := ReadLines(strings.NewReader("example.com\n"), func(string) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("callback error: %v", err)
	}
	if err := ReadLines(strings.NewReader(strings.Repeat("x", 1<<20)), func(string) error { return nil }); err == nil {
		t.Fatal("accepted oversized line")
	}
}
