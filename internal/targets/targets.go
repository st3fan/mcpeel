// Package targets parses host-list input and generates a small set of MCP URLs.
package targets

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Target retains whether HTTPS was inferred, so only those inputs may use HTTP fallback.
type Target struct {
	Input      string
	URL        url.URL
	AutoScheme bool
}

// Candidate is an endpoint to probe. Fallback permits HTTP after an HTTPS connection failure.
type Candidate struct {
	Input    string
	URL      string
	Fallback bool
}

// ReadLines streams nonempty, non-comment input, with a 1 MiB maximum line size.
func ReadLines(r io.Reader, emit func(string) error) error {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 1<<20)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := emit(line); err != nil {
			return err
		}
	}
	return s.Err()
}

// Parse accepts a DNS name, address, or HTTP(S) URL, with an optional port/path/query.
func Parse(input string) (Target, error) {
	input = strings.TrimSpace(input)
	t := Target{Input: input, AutoScheme: !strings.Contains(input, "://")}
	if input == "" || strings.ContainsAny(input, "\r\n\t ") {
		return t, fmt.Errorf("expected a host or HTTP(S) URL without whitespace")
	}
	raw := input
	if t.AutoScheme {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return t, fmt.Errorf("invalid target: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return t, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return t, fmt.Errorf("credentials and fragments are not supported")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return t, fmt.Errorf("missing host")
	}
	addr, ipErr := netip.ParseAddr(host)
	if ipErr != nil && !validDNS(host) {
		return t, fmt.Errorf("invalid host %q", host)
	}
	if ipErr == nil && addr.Is6() && !strings.HasPrefix(u.Host, "[") {
		return t, fmt.Errorf("IPv6 addresses must be bracketed")
	}
	if strings.HasPrefix(u.Host, "[") && (ipErr != nil || !addr.Is6()) {
		return t, fmt.Errorf("brackets require an IPv6 address")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return t, fmt.Errorf("port must be between 1 and 65535")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return t, fmt.Errorf("missing port after colon")
	}
	u.Host = host
	if ipErr == nil && addr.Is6() {
		u.Host = "[" + host + "]"
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	t.URL = *u
	return t, nil
}

func validDNS(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Candidates tries the exact supplied URL first, then defaults on the origin and mcp. host.
// It never infers parent domains or adds a prefix to addresses or localhost.
func Candidates(t Target, subdomain bool) []Candidate {
	var out []Candidate
	seen := make(map[string]bool)
	add := func(u url.URL) {
		s := u.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, Candidate{Input: t.Input, URL: s, Fallback: t.AutoScheme})
		}
	}
	add(t.URL)
	origins := []url.URL{t.URL}
	host := t.URL.Hostname()
	_, ipErr := netip.ParseAddr(host)
	if subdomain && ipErr != nil && host != "localhost" && !strings.HasSuffix(host, ".localhost") && !strings.HasPrefix(host, "mcp.") {
		u := t.URL
		u.Host = "mcp." + host
		if port := t.URL.Port(); port != "" {
			u.Host = net.JoinHostPort(u.Host, port)
		}
		origins = append(origins, u)
	}
	for _, origin := range origins {
		for _, path := range []string{"/", "/mcp", "/sse", "/mcp/sse", "/api/mcp"} {
			u := origin
			u.Path, u.RawPath, u.RawQuery, u.ForceQuery = path, "", "", false
			add(u)
		}
	}
	return out
}
