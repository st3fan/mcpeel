# mcpeel

Find HTTP-accessible MCP servers from a list of hosts. `mcpeel` checks a small set of endpoint paths and the `mcp.` hostname, then confirms findings through an MCP protocol exchange.

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
| `-j`, `-json` | Emit findings as JSON Lines |
| `-v` | Show unconfirmed candidate diagnostics on stderr |
| `-h` | Show help |

File, target, and piped input can be combined. Inputs are collected before probing to deduplicate overlapping candidates; findings stream as workers finish. With no supplied input, the command shows usage. Ctrl-C cancels pending requests.

Each generated endpoint URL has its own timeout budget, shared across discovery, initialization, version retries, and HTTPS-to-HTTP fallback. The different paths and hostnames generated from one input host have independent budgets. A timed-out endpoint does not stop the remaining scan.

Each host is checked at `/`, `/mcp`, `/sse`, `/mcp/sse`, and `/api/mcp`. An explicit path and query are also checked exactly as supplied. For `example.com`, the same default paths are tried on `mcp.example.com`. These paths are heuristics, not standardized endpoint locations.

Expansion adds a prefix to the supplied hostname: `api.example.com` becomes `mcp.api.example.com`. It does not infer parent domains. IP addresses, localhost (including `.localhost` names), and names already starting with `mcp.` are not expanded. Explicit schemes and ports are preserved.

For schemeless inputs, HTTPS is tried first, with HTTP fallback only after a connection or TLS failure. A responding HTTPS server does not trigger HTTP fallback merely because no MCP endpoint was found. Explicit HTTPS URLs never fall back. TLS certificates are verified. Up to three redirects may be followed on the same hostname, without HTTPS downgrade; POST requests only follow 307/308 redirects so the request body is preserved.

Detection supports [current discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover) (`2026-07-28`), [initialization-based HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle) (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`), and deprecated HTTP+SSE. JSON and SSE responses must contain a matching JSON-RPC response and a valid MCP result. Legacy SSE endpoints must advertise a POST endpoint on the same origin and complete initialization. Streams and responses are bounded to 1 MiB; initialization sessions receive a best-effort cleanup, bounded to an additional 250ms.

Default output is one confirmed endpoint URL per line. `-j` or `-json` emits one JSON object per line, including the original input, final endpoint URL, transport, detection method, advertised protocol versions, and server identity when supplied. Server identity is self-reported. Output order depends on response times. Diagnostics always go to stderr.

HTML mentioning MCP, arbitrary JSON-RPC/SSE, and bare HTTP status codes do not confirm a server. Authentication-blocked endpoints can remain undiscovered; this version does not log in, crawl websites, scan ports, call tools, or fetch resources/prompts. Zero findings does not prove that no MCP server exists.

Exit status is `0` for a completed scan (including zero findings), `1` for missing/invalid-only input, input-source errors or output errors, `2` for invalid command usage, and `130` for cancellation. Unreachable hosts do not abort the scan.

Validate with local fixtures:

```sh
go test ./...
go test -race ./...
go vet ./...
```
