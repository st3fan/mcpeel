package probe

import "slices"

const (
	StreamableHTTP = "streamable-http"
	HTTPSSE        = "http+sse"
)

// TransportEvidence records a successful protocol exchange for one transport.
type TransportEvidence struct {
	Method           string      `json:"method"`
	ProtocolVersions []string    `json:"protocol_versions"`
	ServerInfo       *ServerInfo `json:"server_info,omitempty"`
}

// Finding represents confirmed transports at one final endpoint URL. The singular
// fields describe the primary transport for compatibility, preferring Streamable HTTP.
type Finding struct {
	Input            string                       `json:"input"`
	URL              string                       `json:"url"`
	Transports       []string                     `json:"transports"`
	TransportDetails map[string]TransportEvidence `json:"transport_details"`
	Transport        string                       `json:"transport"`
	Method           string                       `json:"method"`
	ProtocolVersions []string                     `json:"protocol_versions"`
	ServerInfo       *ServerInfo                  `json:"server_info,omitempty"`
}

func newFinding(endpoint, transport, method string, versions []string, info *ServerInfo) *Finding {
	f := &Finding{URL: endpoint}
	f.Merge(Finding{TransportDetails: map[string]TransportEvidence{
		transport: {Method: method, ProtocolVersions: versions, ServerInfo: info},
	}})
	return f
}

// Merge combines confirmed evidence for the same URL. Callers group by URL first.
func (f *Finding) Merge(other Finding) {
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
		if !exists || incoming.Method == "server/discover" && detail.Method != "server/discover" {
			detail = incoming
		}
		if detail.ServerInfo == nil {
			detail.ServerInfo = incoming.ServerInfo
		}
		detail.ProtocolVersions = versions
		f.TransportDetails[transport] = detail
	}
	f.Transports = nil
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
