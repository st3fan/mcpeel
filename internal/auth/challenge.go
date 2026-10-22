// Package auth records advertised HTTP authentication without attempting a login.
package auth

import (
	"fmt"
	"strings"
)

type Challenge struct {
	Scheme     string            `json:"scheme,omitempty"`
	Parameters map[string]string `json:"parameters,omitempty"`
	Token68    string            `json:"token68,omitempty"`
	Raw        string            `json:"raw"`
	ParseError string            `json:"parse_error,omitempty"`
}

// ParseChallenges handles repeated fields and comma lists without splitting quoted values.
// Invalid challenges remain visible but are not used to identify authentication schemes.
func ParseChallenges(values []string) []Challenge {
	var out []Challenge
	for _, value := range values {
		var groups []string
		for _, part := range commaParts(value) {
			name, rest := token(strings.TrimSpace(part))
			if name != "" && strings.HasPrefix(strings.TrimSpace(rest), "=") && len(groups) != 0 {
				groups[len(groups)-1] += "," + part
			} else if strings.TrimSpace(part) != "" {
				groups = append(groups, part)
			}
		}
		for _, group := range groups {
			out = append(out, parseChallenge(strings.TrimSpace(group)))
		}
	}
	return out
}

func commaParts(s string) []string {
	var parts []string
	quoted, escaped, start := false, false, 0
	for i := range len(s) {
		c := s[i]
		if escaped {
			escaped = false
		} else if quoted && c == '\\' {
			escaped = true
		} else if c == '"' {
			quoted = !quoted
		} else if c == ',' && !quoted {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func token(s string) (string, string) {
	i := 0
	for i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' || s[i] >= '0' && s[i] <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(s[i]))) {
		i++
	}
	return s[:i], s[i:]
}

func parseChallenge(raw string) Challenge {
	c := Challenge{Raw: raw}
	scheme, rest := token(raw)
	if scheme == "" || rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		c.ParseError = "invalid authentication scheme"
		return c
	}
	c.Scheme = scheme
	for _, known := range []string{"Basic", "Digest", "Bearer", "Negotiate"} {
		if strings.EqualFold(known, scheme) {
			c.Scheme = known
		}
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return c
	}
	if validToken68(rest) {
		c.Token68 = rest
		return c
	}
	c.Parameters = make(map[string]string)
	for _, part := range commaParts(rest) {
		name, value := token(strings.TrimSpace(part))
		value = strings.TrimSpace(value)
		if name == "" || !strings.HasPrefix(value, "=") {
			c.ParseError = "invalid authentication parameter"
			break
		}
		name = strings.ToLower(name)
		if _, exists := c.Parameters[name]; exists {
			c.ParseError = "duplicate authentication parameter"
			break
		}
		decoded, err := parameterValue(strings.TrimSpace(value[1:]))
		if err != nil {
			c.ParseError = err.Error()
			break
		}
		c.Parameters[name] = decoded
	}
	return c
}

func validToken68(s string) bool {
	n := 0
	for n < len(s) && (s[n] >= 'a' && s[n] <= 'z' || s[n] >= 'A' && s[n] <= 'Z' || s[n] >= '0' && s[n] <= '9' || strings.ContainsRune("-._~+/", rune(s[n]))) {
		n++
	}
	return n > 0 && strings.Trim(s[n:], "=") == ""
}

func parameterValue(s string) (string, error) {
	if !strings.HasPrefix(s, `"`) {
		v, rest := token(s)
		if v != "" && rest == "" {
			return v, nil
		}
		return "", fmt.Errorf("invalid parameter value")
	}
	var out strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			if strings.TrimSpace(s[i+1:]) == "" {
				return out.String(), nil
			}
			return "", fmt.Errorf("characters after quoted value")
		}
		if c == '\\' {
			i++
			if i == len(s) {
				break
			}
			c = s[i]
		}
		if c < 32 && c != '\t' || c == 127 {
			return "", fmt.Errorf("invalid control character")
		}
		out.WriteByte(c)
	}
	return "", fmt.Errorf("unterminated quoted value")
}
