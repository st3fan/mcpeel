# mcpeel

Find HTTP-accessible MCP servers from a list of hosts. `mcpeel` checks a small set of endpoint paths and the `mcp.` hostname, then confirms whether each endpoint supports Streamable HTTP, legacy HTTP+SSE, or both.

Requires Go 1.27.1 or later. Build or install the command:

```sh
go build -o mcpeel ./cmd/mcpeel
go install github.com/st3fan/mcpeel/cmd/mcpeel@latest
```

```sh
cat hosts.txt | mcpeel
mcpeel -l hosts.txt
mcpeel -u example.com -u https://api.example.net/custom/mcp
mcpeel -l hosts.txt -json -c 10 -timeout 2.5s
```

Input can contain DNS names, IPv4 addresses, bracketed IPv6 addresses, ports, or HTTP(S) URLs. Schemeless paths such as `example.com/mcp` also work. Blank lines and lines beginning with `#` are ignored. Repeated targets and candidate URLs are deduplicated. Invalid targets are reported to stderr while valid targets continue.

| Flag | Purpose |
| --- | --- |
| `-u`, `-target` | Target host or URL; repeat for multiple targets |
| `-l`, `-list` | Newline-delimited input file; `-` reads stdin |
| `-c` | Maximum concurrent candidate exchanges; default `10` |
| `-timeout` | Deadline per target endpoint; default `2.5s` (e.g. `750ms` or `10s` to override) |
| `-no-subdomain` | Disable `mcp.` hostname expansion |
| `-j`, `-json` | Emit endpoint, transport, and authentication evidence as JSON Lines |
| `-v` | Show unconfirmed candidate diagnostics on stderr |
| `-h` | Show help |

File, target, and piped input can be combined. Inputs are collected before probing to deduplicate overlapping candidates. Plain URLs stream as workers finish; JSONL findings are emitted when scanning completes so evidence from aliases and redirects can be merged into one record per final URL. With no supplied input, the command shows usage. Ctrl-C cancels pending requests.

Each generated endpoint URL has its own timeout budget, shared across both transport checks, discovery, initialization, version retries, and HTTPS-to-HTTP fallback. The two transport checks run concurrently, so a stalled check cannot prevent the other transport from being confirmed. The different paths and hostnames generated from one input host have independent budgets. A timed-out endpoint does not stop the remaining scan.

Each host is checked at `/`, `/mcp`, `/sse`, `/mcp/sse`, and `/api/mcp`. An explicit path and query are also checked exactly as supplied. For `example.com`, the same default paths are tried on `mcp.example.com`. These paths are heuristics, not standardized endpoint locations.

Expansion adds a prefix to the supplied hostname: `api.example.com` becomes `mcp.api.example.com`. It does not infer parent domains. IP addresses, localhost (including `.localhost` names), and names already starting with `mcp.` are not expanded. Explicit schemes and ports are preserved.

For schemeless inputs, HTTPS is tried first, with HTTP fallback only after a connection or TLS failure. A responding HTTPS server does not trigger HTTP fallback merely because no MCP endpoint was found. Explicit HTTPS URLs never fall back. TLS certificates are verified. Up to three redirects may be followed on the same hostname, without HTTPS downgrade; POST requests only follow 307/308 redirects so the request body is preserved.

Detection supports [current discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) (`2026-07-28`), [initialization-based HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`), and deprecated HTTP+SSE. JSON and SSE responses must contain a matching JSON-RPC response and a valid MCP result. Legacy SSE endpoints must advertise a POST endpoint on the same origin and complete initialization. Streams and responses are bounded to 1 MiB; initialization sessions receive a best-effort cleanup, bounded to an additional 250ms.

When discovery fails, mcpeel can fall back to initialization within the same endpoint deadline, including when an older server returns HTTP 5xx for discovery. A valid initialization exchange is still required for confirmation. Discovery responses with HTTP 401/403 or explicit modern-only protocol errors stop this fallback.

Both transports are checked even when one succeeds. Streamable HTTP may encode its POST response as SSE; that alone does not confirm the legacy HTTP+SSE transport, which requires a GET stream advertising a separate POST channel and successful initialization. Only confirmed transports appear in results. An omitted transport can be unconfirmed because of a timeout or failed check; omission does not prove it is unsupported.

Default output is one confirmed endpoint URL per line. `-j` or `-json` emits one JSON object per endpoint, including the original input, final URL, a `transports` list, and a `transport_details` object keyed by transport. Each detail contains its detection method, advertised protocol versions, and server identity when supplied. A dual-transport endpoint has `"transports": ["streamable-http", "http+sse"]`.

Each transport detail also contains `response_headers` from its final confirming HTTP response. Streamable HTTP uses the discovery or initialization POST response; legacy HTTP+SSE uses the endpoint's GET stream response. Legacy SSE additionally includes `post_endpoint` and `post_response_headers` for its initialization POST channel. Header names use canonical HTTP casing, and values are arrays that preserve repeated fields such as `Set-Cookie`.

For example, the header portion of a JSONL finding can contain:

```json
{"response_headers":{"Content-Type":["application/json"],"Set-Cookie":["a=1; Path=/","b=2; Path=/"]}}
```

When aliases are combined, headers follow the selected confirmation evidence. Redirect, failed-probe, initialization-notification, and cleanup response headers are excluded from that evidence.

The existing singular `transport`, `method`, `protocol_versions`, and `server_info` fields remain for compatibility. They describe the primary confirmed transport, preferring Streamable HTTP when both are found. Protocol versions from repeated observations of the same transport are combined, with discovery evidence preferred over initialization evidence. Different final URLs remain separate findings even when one input redirects its POST and GET requests differently. Server identity is self-reported. Output order depends on response times. Diagnostics always go to stderr.

JSONL also reports authentication evidence in an `authentication` array. Each observation identifies the exact response URL, attempted transport, request method and stage, HTTP status, response headers, raw and parsed `WWW-Authenticate` challenges, advertised schemes, and any metadata-discovery outcome. Legacy SSE GET and initialization POST observations remain distinct. Duplicate aliases merge their observations without discarding an auth challenge when another probe succeeds.

| Authentication state | Meaning |
| --- | --- |
| `anonymous_probe` | A valid MCP exchange succeeded without credentials for this tested operation |
| `required` | HTTP 401, or HTTP 403 with an explicit usable authentication/scope challenge |
| `unknown` | The response does not establish an access policy, such as bare 403, a blocked redirect, or a failed check |

Every JSONL record includes `mcp_confirmed`. Auth-blocked candidates and blocked redirects can appear with `mcp_confirmed: false`, empty `transports`, and no fabricated server identity or protocol version. Plain output continues to contain only protocol-confirmed MCP URLs. Unreachable hosts and ordinary responses without MCP/authentication evidence remain diagnostics rather than auth findings.

These abbreviated JSONL examples show the access states (full records also include URLs, headers, and other evidence):

```json
{"mcp_confirmed":true,"authentication":[{"state":"anonymous_probe","stage":"server/discover"}]}
{"mcp_confirmed":false,"authentication":[{"state":"required","http_status":401,"schemes":["Bearer"]}]}
{"mcp_confirmed":false,"authentication":[{"state":"unknown","http_status":403}]}
```

Supported HTTP challenge parsing includes Basic, Digest, Bearer, Negotiate, and other advertised scheme names, including repeated headers and multiple challenges with quoted parameters. A Bearer challenge alone does not establish OAuth, token format (JWT/opaque), or provider identity. API-key, cookie, and client-certificate requirements can remain unknown. A successful discovery probe does not prove that tools, resources, or other operations are public; mcpeel does not invoke them to test access.

When advertised or appropriate for a 401/Bearer response, mcpeel can fetch OAuth protected-resource metadata from a challenge's `resource_metadata` URL or the endpoint-specific/root `/.well-known/oauth-protected-resource` locations. It records document URLs and outcomes (`validated`, `invalid`, `unavailable`, `external`, or `not_attempted`). A validated document must name the exact protected request URL in its `resource` field. Advertised authorization-server URLs, supported scopes, and token-presentation methods are retained; required scopes from a challenge remain separate from metadata's supported scopes. `oauth_advertised: true` means that resource-bound metadata advertised OAuth support, and does not confirm MCP support or require authentication for every operation.

Metadata discovery shares the endpoint timeout and permits at most three distinct fetches per endpoint probe, each with the existing redirect limit and a 1 MiB body limit. Concurrent observations share fetches. Only same-origin metadata is fetched, including through redirects. External metadata and authorization-server URLs remain references. No login, client registration, token exchange, or credential guessing is performed.

HTML mentioning MCP, arbitrary JSON-RPC/SSE, HTTP authentication challenges, and OAuth metadata do not by themselves confirm an MCP server. Authentication-blocked endpoints can remain unconfirmed. This version does not log in, crawl websites, scan ports, call tools, or fetch resources/prompts. Zero findings does not prove that no MCP server exists.

Exit status is `0` for a completed scan (including zero findings), `1` for missing/invalid-only input, input-source errors or output errors, `2` for invalid command usage, and `130` for cancellation. Unreachable hosts do not abort the scan.

Validate with local fixtures:

```sh
go test ./...
go test -race ./...
go vet ./...
```
