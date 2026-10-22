package auth

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestChallenges(t *testing.T) {
	values := []string{`Basic realm="a,b", charset="UTF-8", bearer realm="say \"hello\"", scope="read write", resource_metadata="https://example.com/meta"`, `Negotiate YWJjZA==, Custom parameter=value`}
	cs := ParseChallenges(values)
	if len(cs) != 4 || cs[0].Scheme != "Basic" || cs[0].Parameters["realm"] != "a,b" || cs[1].Scheme != "Bearer" || cs[1].Parameters["realm"] != `say "hello"` || cs[1].Parameters["scope"] != "read write" || cs[2].Token68 != "YWJjZA==" || cs[3].Scheme != "Custom" || cs[3].Parameters["parameter"] != "value" {
		t.Fatalf("incorrect challenges: %+v", cs)
	}
	for _, c := range cs {
		if c.ParseError != "" || c.Raw == "" {
			t.Fatalf("lost valid/raw challenge: %+v", c)
		}
	}
	for _, raw := range []string{`Bearer realm="unterminated`, `Basic realm="one", REALM="two"`, `=bad`, "Basic realm=\"bad\nvalue\"", `Bearer realm="a" trailing`} {
		cs := ParseChallenges([]string{raw})
		if len(cs) != 1 || cs[0].ParseError == "" || cs[0].Raw != raw {
			t.Fatalf("malformed challenge was not preserved: %q: %+v", raw, cs)
		}
	}
	if cs := ParseChallenges([]string{"", ", ,"}); len(cs) != 0 {
		t.Fatalf("empty values became challenges: %+v", cs)
	}
}

func TestObservationStatesAndSnapshot(t *testing.T) {
	for _, tt := range []struct {
		status        int
		header, state string
	}{
		{200, "", Unknown}, {401, "", Required}, {401, "Bearer", Required},
		{403, "", Unknown}, {403, `Bearer error="insufficient_scope", scope="write"`, Required},
		{403, `Basic realm="broken`, Unknown},
	} {
		r := &http.Response{StatusCode: tt.status, Header: http.Header{}, Request: httptest.NewRequest("POST", "https://example.com/mcp", nil)}
		if tt.header != "" {
			r.Header.Add("WWW-Authenticate", tt.header)
		}
		o := Observe(r, "streamable-http", "server/discover")
		if o.State != tt.state || o.URL != "https://example.com/mcp" || o.Method != "POST" || o.Stage != "server/discover" {
			t.Fatalf("observation: %+v", o)
		}
		copy := o.Clone()
		r.Header.Set("WWW-Authenticate", "changed")
		if len(o.RawChallenges) != 0 && !reflect.DeepEqual(copy.RawChallenges, []string{tt.header}) {
			t.Fatal("lost raw challenge")
		}
		if len(o.Challenges) != 0 && len(o.Challenges[0].Parameters) != 0 {
			o.Challenges[0].Parameters["scope"] = "changed"
			if copy.Challenges[0].Parameters["scope"] == "changed" {
				t.Fatal("challenge parameters alias clone")
			}
		}
		if copy.ResponseHeaders.Get("WWW-Authenticate") != tt.header {
			t.Fatal("headers alias response")
		}
	}
}
