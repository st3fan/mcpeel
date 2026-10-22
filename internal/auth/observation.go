package auth

import (
	"maps"
	"net/http"
	"slices"
)

const (
	AnonymousProbe = "anonymous_probe"
	Required       = "required"
	Unknown        = "unknown"
)

// ResourceMetadata describes an advertised/discovered document, not proof of MCP support.
type ResourceMetadata struct {
	URL                    string   `json:"url"`
	Source                 string   `json:"source"`
	State                  string   `json:"state"`
	HTTPStatus             int      `json:"http_status,omitempty"`
	Resource               string   `json:"resource,omitempty"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	Error                  string   `json:"error,omitempty"`
}

// Observation applies to one transport and request stage, never all server operations.
type Observation struct {
	URL             string             `json:"url"`
	Transport       string             `json:"transport"`
	Stage           string             `json:"stage"`
	Method          string             `json:"method"`
	State           string             `json:"state"`
	HTTPStatus      int                `json:"http_status,omitempty"`
	ResponseHeaders http.Header        `json:"response_headers,omitempty"`
	RawChallenges   []string           `json:"raw_challenges,omitempty"`
	Challenges      []Challenge        `json:"challenges,omitempty"`
	Schemes         []string           `json:"schemes,omitempty"`
	Metadata        []ResourceMetadata `json:"metadata,omitempty"`
	OAuthAdvertised bool               `json:"oauth_advertised,omitempty"`
	Error           string             `json:"error,omitempty"`
}

// Observe snapshots headers before any response body is read. A successful body
// must later be validated before the state can be promoted to anonymous_probe.
func Observe(r *http.Response, transport, stage string) Observation {
	o := Observation{URL: r.Request.URL.String(), Transport: transport, Stage: stage,
		Method: r.Request.Method, State: Unknown, HTTPStatus: r.StatusCode,
		ResponseHeaders: r.Header.Clone(), RawChallenges: slices.Clone(r.Header.Values("WWW-Authenticate"))}
	o.Challenges = ParseChallenges(o.RawChallenges)
	for _, c := range o.Challenges {
		if c.ParseError == "" && !slices.Contains(o.Schemes, c.Scheme) {
			o.Schemes = append(o.Schemes, c.Scheme)
		}
	}
	if r.StatusCode == 401 || r.StatusCode == 403 && len(o.Schemes) != 0 {
		o.State = Required
	}
	return o
}

func (o Observation) Clone() Observation {
	o.ResponseHeaders = o.ResponseHeaders.Clone()
	o.RawChallenges = slices.Clone(o.RawChallenges)
	o.Schemes = slices.Clone(o.Schemes)
	o.Challenges = slices.Clone(o.Challenges)
	for i := range o.Challenges {
		o.Challenges[i].Parameters = maps.Clone(o.Challenges[i].Parameters)
	}
	o.Metadata = slices.Clone(o.Metadata)
	for i := range o.Metadata {
		o.Metadata[i].AuthorizationServers = slices.Clone(o.Metadata[i].AuthorizationServers)
		o.Metadata[i].ScopesSupported = slices.Clone(o.Metadata[i].ScopesSupported)
		o.Metadata[i].BearerMethodsSupported = slices.Clone(o.Metadata[i].BearerMethodsSupported)
	}
	return o
}
