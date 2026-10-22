package probe

import (
	"net/http"
	"reflect"
	"testing"
)

func TestMergeCopiesResponseHeaders(t *testing.T) {
	headers := http.Header{"x-fixture": {"get"}, "set-cookie": {"a=1", "b=2"}}
	postHeaders := http.Header{"x-fixture": {"post"}}
	source := Finding{TransportDetails: map[string]TransportEvidence{
		HTTPSSE: {Method: "initialize", ResponseHeaders: headers, PostEndpoint: "https://example.com/messages", PostResponseHeaders: postHeaders},
	}}
	f := &Finding{URL: "https://example.com/sse"}
	f.Merge(source)
	// Mutating either source map or its value slices must not change the snapshot.
	headers["x-fixture"][0] = "changed"
	headers["set-cookie"][0] = "changed=1"
	headers["X-New"] = []string{"changed"}
	postHeaders["x-fixture"][0] = "changed"
	detail := f.TransportDetails[HTTPSSE]
	if detail.ResponseHeaders.Get("X-Fixture") != "get" || !reflect.DeepEqual(detail.ResponseHeaders["Set-Cookie"], []string{"a=1", "b=2"}) || detail.ResponseHeaders.Get("X-New") != "" ||
		detail.PostResponseHeaders.Get("X-Fixture") != "post" || detail.PostEndpoint != "https://example.com/messages" {
		t.Fatalf("merged headers alias their source or lack canonical names: %+v", detail)
	}
	// A second merge must also own its header snapshots independently.
	other := &Finding{URL: f.URL}
	other.Merge(*f)
	detail.ResponseHeaders["X-Fixture"][0] = "changed again"
	detail.PostResponseHeaders["X-Fixture"][0] = "changed again"
	if other.TransportDetails[HTTPSSE].ResponseHeaders.Get("X-Fixture") != "get" || other.TransportDetails[HTTPSSE].PostResponseHeaders.Get("X-Fixture") != "post" {
		t.Fatalf("duplicate merge retained shared header slices: %+v", other)
	}
}
