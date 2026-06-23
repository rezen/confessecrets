package scanner

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/magiconair/properties"
)

// PropertiesDetector handles Java-style .properties files. It parses with
// magiconair/properties and falls back to line-based scanning for input that
// doesn't parse cleanly, mirroring the JSON/YAML detectors.
type PropertiesDetector struct{}

func (PropertiesDetector) Detect(file string, data []byte, rules []Rule) []Finding {
	root, err := parseProperties(data)
	if err != nil {
		return detectPropertiesLines(file, data, rules)
	}

	return detectStructured(file, root, rules)
}

// parseProperties loads .properties bytes into a flat map for detectStructured.
// Expansion is disabled so values are reported exactly as written (e.g.
// "${VAULT_PW}" stays literal rather than being interpolated) and so the
// library's expansion-failure path — which exits the process via its default
// ErrorHandler — can never fire on untrusted input.
func parseProperties(data []byte) (map[string]any, error) {
	loader := properties.Loader{Encoding: properties.UTF8, DisableExpansion: true}

	p, err := loader.LoadBytes(data)
	if err != nil {
		return nil, err
	}

	root := make(map[string]any, p.Len())
	for _, key := range p.Keys() {
		if v, ok := p.Get(key); ok {
			root[key] = v
		}
	}

	return root, nil
}

// detectPropertiesLines scans a Java-style .properties file. It honors the
// format's conventions: '#' and '!' begin comments, keys and values are
// separated by '=', ':', or whitespace, a logical line may span several
// physical lines via a trailing backslash, and backslash escapes (\=, \:, \t,
// \uXXXX, ...) are decoded before matching.
func detectPropertiesLines(file string, data []byte, rules []Rule) []Finding {
	var findings []Finding
	lines := strings.Split(string(data), "\n")

	for i := 0; i < len(lines); i++ {
		stripped := trimPropertiesLeading(strings.TrimRight(lines[i], "\r"))

		if stripped == "" || stripped[0] == '#' || stripped[0] == '!' {
			continue
		}

		// A logical line absorbs following physical lines while it ends with an
		// odd number of backslashes; their leading whitespace is dropped.
		startLine := i
		logical := stripped
		for propertyLineContinues(logical) {
			logical = logical[:len(logical)-1]
			i++
			if i >= len(lines) {
				break
			}
			logical += trimPropertiesLeading(strings.TrimRight(lines[i], "\r"))
		}

		rawKey, rawValue, ok := splitProperty(logical)
		if !ok {
			continue
		}

		key := unescapeProperty(rawKey)
		value := unescapeProperty(rawValue)

		for _, rule := range rules {
			if !nameSignalsSecret(key, rule) {
				continue
			}

			if shouldSkipValue(value, rule) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" && !isLikelySecretValue(value, rule.MinValueLen) {
				continue
			}
			if reason == "" {
				reason = "properties key indicates secret and value is populated"
			}

			findings = append(findings, newFinding(
				file,
				fmt.Sprintf("line:%d", startLine+1),
				"properties_key",
				"properties_value",
				key,
				value,
				reason,
			))
		}

		findings = append(findings, detectValuePatterns(file, fmt.Sprintf("line:%d", startLine+1), key, value, rules)...)
	}

	return findings
}

// trimPropertiesLeading strips the leading whitespace the .properties format
// ignores (space, tab, form feed).
func trimPropertiesLeading(s string) string {
	return strings.TrimLeft(s, " \t\f")
}

// propertyLineContinues reports whether line ends with an unescaped trailing
// backslash, i.e. an odd number of backslashes, signaling line continuation.
func propertyLineContinues(line string) bool {
	count := 0
	for j := len(line) - 1; j >= 0 && line[j] == '\\'; j-- {
		count++
	}
	return count%2 == 1
}

// splitProperty divides a logical .properties line into its key and value at the
// first unescaped key terminator: whitespace, '=', or ':'. Surrounding
// whitespace and one optional '='/':' separator are consumed. ok is false when
// the line has no key.
func splitProperty(line string) (key, value string, ok bool) {
	var keyBuf strings.Builder
	i, n := 0, len(line)

	for i < n {
		c := line[i]
		if c == '\\' && i+1 < n {
			keyBuf.WriteByte(c)
			keyBuf.WriteByte(line[i+1])
			i += 2
			continue
		}
		if c == ' ' || c == '\t' || c == '\f' || c == '=' || c == ':' {
			break
		}
		keyBuf.WriteByte(c)
		i++
	}

	if keyBuf.Len() == 0 {
		return "", "", false
	}

	for i < n && (line[i] == ' ' || line[i] == '\t' || line[i] == '\f') {
		i++
	}
	if i < n && (line[i] == '=' || line[i] == ':') {
		i++
		for i < n && (line[i] == ' ' || line[i] == '\t' || line[i] == '\f') {
			i++
		}
	}

	return keyBuf.String(), line[i:], true
}

// unescapeProperty decodes the backslash escapes a .properties file may use in
// keys and values (\t, \n, \r, \f, \uXXXX, and \<char> for everything else).
func unescapeProperty(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}

	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}

		i++
		switch s[i] {
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 'f':
			b.WriteByte('\f')
		case 'u':
			if i+4 < len(s) {
				if r, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil {
					b.WriteRune(rune(r))
					i += 4
					continue
				}
			}
			b.WriteByte('u')
		default:
			b.WriteByte(s[i])
		}
	}

	return b.String()
}
