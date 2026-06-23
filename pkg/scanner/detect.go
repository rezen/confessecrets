package scanner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Reasons returned by classifySecretReason identifying why a value looks secret.
const (
	reasonJWTIndicator              = "jwt_indicator"
	reasonURLSecretQueryParam       = "url_secret_query_param"
	reasonURLCredentials            = "url_credentials"
	reasonPrivateKeyIndicator       = "private_key_indicator"
	reasonConnectionStringIndicator = "connection_string_secret_indicator"
)

var secretQueryParamRe = regexp.MustCompile(
	`(?i)(token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|secret|sig|signature|credential|password|passwd|pwd)`,
)

// Detector parses one file format's bytes (already BOM-stripped) into findings.
// Each supported format provides a concrete implementation.
type Detector interface {
	Detect(file string, data []byte, rules []Rule) []Finding
}

// detectorFor returns the Detector for path's format, or nil if the file type is
// not supported.
func detectorFor(path string) Detector {
	if isEnvFile(path) {
		return DotenvDetector{}
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".jsonc":
		return JSONDetector{}
	case ".yaml", ".yml":
		return YAMLDetector{}
	case ".xml":
		return XMLDetector{}
	case ".properties":
		return PropertiesDetector{}
	case ".ini":
		return INIDetector{}
	}

	return nil
}

func detectStructured(file string, root any, rules []Rule) []Finding {
	var findings []Finding

	var walkNode func(any, string)
	walkNode = func(node any, path string) {
		switch v := node.(type) {
		case map[string]any:
			for _, rule := range rules {
				findings = append(findings, detectInObject(file, v, path, rule)...)
				findings = append(findings, detectMapKeyValues(file, v, path, rule)...)
			}

			for key, child := range v {
				walkNode(child, joinPath(path, key))
			}

		case []any:
			for i, child := range v {
				walkNode(child, fmt.Sprintf("%s[%d]", path, i))
			}

		case string:
			// Value scanning: flag any scalar whose shape matches a known
			// secret token, regardless of its key name.
			findings = append(findings, detectValuePatterns(file, path, lastSegment(path), v, rules)...)
		}
	}

	walkNode(root, "$")
	return findings
}

func detectInObject(file string, obj map[string]any, basePath string, rule Rule) []Finding {
	var findings []Finding

	for _, namePath := range rule.NamePaths {
		name, ok := lookupString(obj, namePath)
		if !ok || !nameSignalsSecret(name, rule) {
			continue
		}

		for _, valuePath := range rule.ValuePaths {
			value, ok := lookupString(obj, valuePath)
			if !ok {
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
				reason = "name field indicates secret and paired value is populated"
			}

			findings = append(findings, newFinding(
				file,
				basePath,
				namePath,
				valuePath,
				name,
				value,
				reason,
			))
		}
	}

	return findings
}

func detectMapKeyValues(file string, obj map[string]any, basePath string, rule Rule) []Finding {
	var findings []Finding

	for key, raw := range obj {
		value, ok := raw.(string)
		if !ok {
			continue
		}

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
			reason = "map key indicates secret and scalar value is populated"
		}

		findings = append(findings, newFinding(
			file,
			joinPath(basePath, key),
			"map_key",
			"map_value",
			key,
			value,
			reason,
		))
	}

	return findings
}

func newFinding(file, path, namePath, valuePath, name, value, reason string) Finding {
	return Finding{
		File:        file,
		Path:        path,
		NamePath:    namePath,
		ValuePath:   valuePath,
		Name:        name,
		Value:       redact(value),
		RawValue:    value,
		ValueSHA256: sha256Hex(value),
		Reason:      reason,
		Meta:        parseJWTMeta(value),
	}
}

func shouldSkipValue(value string, rule Rule) bool {
	return shouldIgnoreValue(value, rule) || isURLWithoutCredentials(value)
}

// nameSignalsSecret reports whether name indicates a secret under rule: it must
// match the rule's NameRegex and not match any of its IgnoreNamePatterns. The
// ignore patterns let benign keys that happen to contain a trigger substring
// (e.g. "label" or "labelKey" matching the "key" alternative) be excluded.
func nameSignalsSecret(name string, rule Rule) bool {
	if !rule.NameRegex.MatchString(name) {
		return false
	}

	for _, re := range rule.IgnoreNamePatterns {
		if re.MatchString(name) {
			return false
		}
	}

	return true
}

func shouldIgnoreValue(value string, rule Rule) bool {
	value = normalizeScalar(value)

	for _, prefix := range rule.IgnoreValuePrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}

	for _, re := range rule.IgnoreValuePatterns {
		if re.MatchString(value) {
			return true
		}
	}

	return false
}

func isLikelySecretValue(value string, minLen int) bool {
	value = strings.TrimSpace(value)

	if value == "" {
		return false
	}

	if classifySecretReason(value) != "" {
		return true
	}

	if strings.Contains(value, "$(") ||
		strings.Contains(value, "${") ||
		strings.Contains(value, "{{") ||
		strings.Contains(value, "}}") {
		return false
	}

	if looksLikeNaturalLanguage(value) {
		return false
	}

	if len(value) < minLen {
		return false
	}

	lower := strings.ToLower(value)

	nonSecrets := map[string]bool{
		"true":      true,
		"false":     true,
		"null":      true,
		"none":      true,
		"changeme":  true,
		"password":  true,
		"example":   true,
		"test":      true,
		"dummy":     true,
		"undefined": true,
	}

	return !nonSecrets[lower]
}

func classifySecretReason(value string) string {
	value = normalizeScalar(value)

	if hasJWTIndicator(value) {
		return reasonJWTIndicator
	}

	if hasSecretQueryParam(value) {
		return reasonURLSecretQueryParam
	}

	if hasURLCredentials(value) {
		return reasonURLCredentials
	}

	if looksLikePrivateKey(value) {
		return reasonPrivateKeyIndicator
	}

	if looksLikeConnectionString(value) {
		return reasonConnectionStringIndicator
	}

	return ""
}

func hasJWTIndicator(value string) bool {
	value = normalizeScalar(value)
	// "eyJ" is the base64url encoding of any JSON object's opening `{"`, so it
	// matches every JWT header regardless of which claim comes first (alg, typ,
	// kid, ...). The space-prefixed form catches tokens behind a "Bearer "
	// (or similar) prefix.
	return strings.HasPrefix(value, "eyJ") || strings.Contains(value, " eyJ")
}

// parseJWTMeta extracts claims from a JWT embedded in value. The standard
// iss/iat/exp claims are mapped to dedicated fields; every other claim is stored
// in Extra. It returns nil when value contains no JWT, the token can't be
// decoded, or it carries no claims, so non-JWT findings carry no Meta.
func parseJWTMeta(value string) *Meta {
	token := extractJWT(value)
	if token == "" {
		return nil
	}

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}

	payload, err := decodeJWTSegment(parts[1])
	if err != nil {
		return nil
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	meta := &Meta{}
	populated := false

	for key, raw := range claims {
		switch key {
		case "iss":
			if s, ok := raw.(string); ok && s != "" {
				meta.Issuer = s
				populated = true
			}
		case "iat":
			if n, ok := raw.(float64); ok && n != 0 {
				meta.Iat = int64(n)
				populated = true
			}
		case "exp":
			if n, ok := raw.(float64); ok && n != 0 {
				meta.Expiration = int64(n)
				meta.IsExpired = meta.Expiration < time.Now().Unix()
				populated = true
			}
		default:
			if meta.Extra == nil {
				meta.Extra = make(map[string]any, len(claims))
			}
			meta.Extra[key] = raw
			populated = true
		}
	}

	if !populated {
		return nil
	}

	return meta
}

// extractJWT returns the JWT substring within value (starting at the "eyJ"
// header marker and running until the next whitespace or quote), or "" if none.
// "eyJ" is the base64url prefix of any JSON header, so this also handles tokens
// behind a "Bearer " prefix and headers that don't start with the alg claim.
func extractJWT(value string) string {
	value = normalizeScalar(value)

	idx := strings.Index(value, "eyJ")
	if idx < 0 {
		return ""
	}

	token := value[idx:]
	if i := strings.IndexAny(token, " \t\r\n\"'"); i >= 0 {
		token = token[:i]
	}

	return token
}

// decodeJWTSegment base64url-decodes a JWT segment, tolerating the missing
// padding that JWTs omit by convention.
func decodeJWTSegment(seg string) ([]byte, error) {
	if m := len(seg) % 4; m != 0 {
		seg += strings.Repeat("=", 4-m)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func hasSecretQueryParam(value string) bool {
	u, ok := parseURL(value)
	if !ok {
		return false
	}

	for key, values := range u.Query() {
		if !secretQueryParamRe.MatchString(key) {
			continue
		}

		for _, v := range values {
			if strings.TrimSpace(v) != "" {
				return true
			}
		}
	}

	return false
}

func hasURLCredentials(value string) bool {
	u, ok := parseURL(value)
	return ok && u.User != nil
}

func isURLWithoutCredentials(value string) bool {
	u, ok := parseURL(value)
	if !ok {
		return false
	}

	if u.User != nil {
		return false
	}

	if hasSecretQueryParam(value) {
		return false
	}

	return true
}

func parseURL(value string) (*url.URL, bool) {
	value = normalizeScalar(value)

	u, err := url.Parse(value)
	if err != nil {
		return nil, false
	}

	if u.Scheme == "" || u.Host == "" {
		return nil, false
	}

	return u, true
}

func looksLikePrivateKey(value string) bool {
	value = strings.ToUpper(value)
	return strings.Contains(value, "BEGIN PRIVATE KEY") ||
		strings.Contains(value, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(value, "BEGIN EC PRIVATE KEY") ||
		strings.Contains(value, "BEGIN OPENSSH PRIVATE KEY")
}

func looksLikeConnectionString(value string) bool {
	lower := strings.ToLower(value)

	hasPassword := strings.Contains(lower, "password=") ||
		strings.Contains(lower, "pwd=") ||
		strings.Contains(lower, "password:") ||
		strings.Contains(lower, "pwd:")

	hasUser := strings.Contains(lower, "user=") ||
		strings.Contains(lower, "user id=") ||
		strings.Contains(lower, "uid=") ||
		strings.Contains(lower, "username=")

	return hasPassword && hasUser
}

func looksLikeNaturalLanguage(value string) bool {

	words := strings.Fields(value)
	if len(words) < 4 {
		return false
	}

	alphaWords := 0
	counted := 0
	for _, word := range words {
		word = strings.Trim(word, `"'.,;:!?()[]{}<>`)

		// Standalone separators (e.g. a lone "-" between phrases) are neither
		// words nor secrets, so they shouldn't count toward the ratio.
		if isPunctuationOnly(word) {
			continue
		}

		counted++
		if isAlphaWord(word) {
			alphaWords++
		}
	}

	if counted == 0 {
		return false
	}

	return float64(alphaWords)/float64(counted) >= 0.80
}

// isPunctuationOnly reports whether word contains no letters and no digits, i.e.
// it is made up entirely of punctuation/separators (or is empty).
func isPunctuationOnly(word string) bool {
	for _, r := range word {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
	}

	return true
}

// isAlphaWord reports whether word reads as a natural-language word: it must
// contain at least one letter and consist only of Unicode letters joined by
// internal hyphens, apostrophes, or slashes. This is script-agnostic, so it
// accepts Latin words as well as words carrying diacritics or written in other
// scripts (e.g. Vietnamese "nhập", Cyrillic, CJK). Allowing these connectors
// lets compound words, contractions, and slashed abbreviations ("donor-derived",
// "mother's", "e/m", "and/or") count as language, while digit-bearing opaque
// tokens ("sk_live_8Fh2", "a1b2") do not.
func isAlphaWord(word string) bool {
	hasLetter := false

	for _, r := range word {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case r == '-' || r == '\'' || r == '’' || r == '/':
			// Internal hyphen/apostrophe/slash joining letters; allowed.
		default:
			return false
		}
	}

	return hasLetter
}

func lookupString(obj map[string]any, dotted string) (string, bool) {
	parts := strings.Split(dotted, ".")
	var cur any = obj

	for _, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}

		cur, ok = m[part]
		if !ok {
			return "", false
		}
	}

	s, ok := cur.(string)
	if !ok {
		return "", false
	}

	s = strings.TrimSpace(s)
	return s, s != ""
}

func normalizeScalar(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return value
}

func redact(value string) string {
	value = normalizeScalar(value)

	if len(value) <= 8 {
		return "********"
	}

	return value[:4] + strings.Repeat("*", 8) + value[len(value)-4:]
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}
