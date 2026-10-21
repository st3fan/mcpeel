package probe

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

const maxResponseBytes = 1 << 20

type rpcError struct {
	Code int `json:"code"`
	Data struct {
		Supported []string `json:"supported"`
	} `json:"data"`
}

type envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

func parseEnvelope(data []byte, id string) (envelope, error) {
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return e, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	if e.JSONRPC != "2.0" || e.ID != id || (len(e.Result) > 0) == (e.Error != nil) {
		return e, fmt.Errorf("invalid or mismatched JSON-RPC response")
	}
	return e, nil
}

func contentType(r *http.Response) string {
	t, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return t
}

func readReply(r *http.Response, id string) (envelope, error) {
	if contentType(r) == "text/event-stream" {
		return newEvents(r.Body).reply(id)
	}
	if contentType(r) != "application/json" {
		return envelope{}, fmt.Errorf("not an MCP JSON/SSE response (HTTP %d)", r.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxResponseBytes+1))
	if err != nil {
		return envelope{}, err
	}
	if len(data) > maxResponseBytes {
		return envelope{}, fmt.Errorf("response exceeds 1 MiB")
	}
	return parseEnvelope(data, id)
}

// events bounds the whole stream, including comments and unrelated events.
type events struct {
	scanner *bufio.Scanner
	limited *io.LimitedReader
}

func newEvents(r io.Reader) *events {
	lr := &io.LimitedReader{R: r, N: maxResponseBytes + 1}
	s := bufio.NewScanner(lr)
	s.Buffer(make([]byte, 4096), maxResponseBytes+1)
	s.Split(splitEventLine)
	return &events{scanner: s, limited: lr}
}

// SSE permits LF, CRLF, and CR line endings.
func splitEventLine(data []byte, atEOF bool) (int, []byte, error) {
	for i, c := range data {
		if c != '\n' && c != '\r' {
			continue
		}
		if c == '\r' && i+1 == len(data) && !atEOF {
			return 0, nil, nil
		}
		n := i + 1
		if c == '\r' && n < len(data) && data[n] == '\n' {
			n++
		}
		return n, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func (s *events) next() (string, []byte, error) {
	name := "message"
	var data []string
	for s.scanner.Scan() {
		if s.limited.N == 0 {
			return "", nil, fmt.Errorf("event stream exceeds 1 MiB")
		}
		line := s.scanner.Text()
		if line == "" {
			if len(data) != 0 {
				return name, []byte(strings.Join(data, "\n")), nil
			}
			name = "message"
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			name = value
		case "data":
			data = append(data, value)
		}
	}
	if err := s.scanner.Err(); err != nil {
		return "", nil, err
	}
	if s.limited.N == 0 {
		return "", nil, fmt.Errorf("event stream exceeds 1 MiB")
	}
	return "", nil, io.EOF
}

func (s *events) reply(id string) (envelope, error) {
	for {
		name, data, err := s.next()
		if err != nil {
			return envelope{}, err
		}
		if name != "message" {
			continue
		}
		// Ignore notifications and other request IDs; only our response can confirm MCP.
		var header struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &header) != nil || header.ID != id {
			continue
		}
		return parseEnvelope(data, id)
	}
}

func object(raw json.RawMessage) bool {
	var v map[string]json.RawMessage
	return json.Unmarshal(raw, &v) == nil && v != nil
}
