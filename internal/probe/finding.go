package probe

import (
	"encoding/json"
	"net/http"
	"slices"

	"github.com/st3fan/mcpeel/internal/auth"
)

const (
	StreamableHTTP = "streamable-http"
	HTTPSSE        = "http+sse"
)

// TransportEvidence records a successful protocol exchange for one transport.
type TransportEvidence struct {
	Method              string      `json:"method"`
	ProtocolVersions    []string    `json:"protocol_versions"`
	ServerInfo          *ServerInfo `json:"server_info,omitempty"`
	ResponseHeaders     http.Header `json:"response_headers"`
	PostEndpoint        string      `json:"post_endpoint,omitempty"`
	PostResponseHeaders http.Header `json:"post_response_headers,omitempty"`
}

// Finding represents confirmed transports at one final endpoint URL. The singular
// fields describe the primary transport for compatibility, preferring Streamable HTTP.
type Finding struct {
	MCPConfirmed     bool                         `json:"mcp_confirmed"`
	Authentication   []auth.Observation           `json:"authentication,omitempty"`
	Input            string                       `json:"input"`
	URL              string                       `json:"url"`
	Transports       []string                     `json:"transports"`
	TransportDetails map[string]TransportEvidence `json:"transport_details"`
	Transport        string                       `json:"transport,omitempty"`
	Method           string                       `json:"method,omitempty"`
	ProtocolVersions []string                     `json:"protocol_versions,omitempty"`
	ServerInfo       *ServerInfo                  `json:"server_info,omitempty"`
}

func newFinding(endpoint, transport, method string, versions []string, info *ServerInfo) *Finding {
	f := &Finding{URL: endpoint, MCPConfirmed: true}
	f.Merge(Finding{TransportDetails: map[string]TransportEvidence{
		transport: {Method: method, ProtocolVersions: versions, ServerInfo: info},
	}})
	return f
}

// Merge combines confirmed evidence for the same URL. Callers group by URL first.
func (f *Finding) Merge(other Finding) {
	f.MCPConfirmed = f.MCPConfirmed || other.MCPConfirmed
	for _, observation := range other.Authentication {
		key, _ := json.Marshal(observation)
		duplicate := false
		for _, existing := range f.Authentication {
			raw, _ := json.Marshal(existing)
			if string(raw) == string(key) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			f.Authentication = append(f.Authentication, observation.Clone())
		}
	}
	if f.TransportDetails == nil {
		f.TransportDetails = make(map[string]TransportEvidence)
	}
	for transport, incoming := range other.TransportDetails {
		detail, exists := f.TransportDetails[transport]
		versions := slices.Clone(detail.ProtocolVersions)
		for _, v := range incoming.ProtocolVersions {
			if !slices.Contains(versions, v) {
				versions = append(versions, v)
			}
		}
		slices.Sort(versions)
		slices.Reverse(versions)
		if incoming.ServerInfo == nil {
			incoming.ServerInfo = detail.ServerInfo
		}
		if !exists || incoming.Method == "server/discover" && detail.Method != "server/discover" {
			detail = incoming
		}
		if detail.ServerInfo == nil {
			detail.ServerInfo = incoming.ServerInfo
		}
		detail.ProtocolVersions = versions
		detail.ResponseHeaders = copyHeaders(detail.ResponseHeaders)
		detail.PostResponseHeaders = copyHeaders(detail.PostResponseHeaders)
		f.TransportDetails[transport] = detail
	}
	f.Transports = make([]string, 0, 2)
	for _, transport := range []string{StreamableHTTP, HTTPSSE} {
		if _, ok := f.TransportDetails[transport]; ok {
			f.Transports = append(f.Transports, transport)
		}
	}
	if len(f.Transports) != 0 {
		f.Transport = f.Transports[0]
		detail := f.TransportDetails[f.Transport]
		f.Method, f.ProtocolVersions, f.ServerInfo = detail.Method, detail.ProtocolVersions, detail.ServerInfo
	}
}

// copyHeaders retains every value while making the finding independent of the
// response or another finding. net/http's usual canonical field names are used.
func copyHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	cloned := make(http.Header, len(headers))
	for name, values := range headers {
		name = http.CanonicalHeaderKey(name)
		cloned[name] = append(cloned[name], values...)
	}
	return cloned
}

func (f *Finding) setResponseHeaders(headers http.Header) {
	detail := f.TransportDetails[f.Transport]
	detail.ResponseHeaders = copyHeaders(headers)
	f.TransportDetails[f.Transport] = detail
}
