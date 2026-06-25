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
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Finding severity levels. levelHigh marks a detected secret (the default for
// every finding); levelInfo marks an informational, non-credential match such as
// a recognized service URL.
const (
	levelHigh = "high"
	levelInfo = "info"
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
	Detect(file string, data []byte, set RuleSet) []Finding
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
	case ".config":
		// .NET configuration files (App.config, web.config, *.dll.config, and
		// Web.{Debug,Release}.config transforms) are XML documents.
		return XMLDetector{}
	case ".properties":
		return PropertiesDetector{}
	case ".ini":
		return INIDetector{}
	}

	// Source-code formats are scanned with tree-sitter (loaded at runtime). When
	// the native libraries are absent, SourceDetector scans nothing.
	if sourceLangForExt(strings.ToLower(filepath.Ext(path))) != nil {
		return SourceDetector{}
	}

	return nil
}

func detectStructured(file string, root any, set RuleSet) []Finding {
	var findings []Finding
	lang := languageName(file)

	var walkNode func(any, string)
	walkNode = func(node any, path string) {
		switch v := node.(type) {
		case map[string]any:
			for _, rule := range set.Rules {
				findings = append(findings, detectInObject(file, v, path, rule, lang)...)
				findings = append(findings, detectMapKeyValues(file, v, path, rule, lang)...)
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
			findings = append(findings, detectValuePatterns(ExaminationFocus{File: file, Path: path, Name: lastSegment(path), Value: v, PrevFindings: recentFindings(findings, set.prevWindow())}, set)...)
		}
	}

	walkNode(root, "$")
	return findings
}

func detectInObject(file string, obj map[string]any, basePath string, rule Rule, lang string) []Finding {
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

			if shouldSkipValue(value, rule, lang) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" && !isLikelySecretValue(name, value, rule, lang) {
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

func detectMapKeyValues(file string, obj map[string]any, basePath string, rule Rule, lang string) []Finding {
	var findings []Finding

	for key, raw := range obj {
		value, ok := raw.(string)
		if !ok {
			continue
		}

		if !nameSignalsSecret(key, rule) {
			continue
		}

		if shouldSkipValue(value, rule, lang) {
			continue
		}

		reason := classifySecretReason(value)
		if reason == "" && !isLikelySecretValue(key, value, rule, lang) {
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
	line := lineFromPath(path)
	// A bare "line:N" path is fully covered by File + Line, so drop it as
	// redundant; structured ("$.a.b") and section-qualified ("[sec] line:N") paths
	// carry location the line number alone does not, and are kept.
	if isBareLinePath(path) {
		path = ""
	}
	return Finding{
		File:                file,
		Path:                path,
		Line:                line,
		Level:               levelHigh,
		NamePath:            namePath,
		ValuePath:           valuePath,
		Name:                name,
		Value:               redact(value),
		RawValue:            value,
		ValueSHA256:         sha256Hex(value),
		Entropy:             valueEntropy(value),
		NameValueSimilarity: round2(nameValueSimilarity(name, value)),
		Reason:              reason,
		Meta:                buildMeta(value),
	}
}

// lineRe extracts the 1-based line number from a finding path produced by the
// line-oriented detectors, which embed it as "line:N" (optionally prefixed with
// an INI section, e.g. "[credentials] line:2").
var lineRe = regexp.MustCompile(`line:(\d+)`)

// lineFromPath returns the source line encoded in a finding path, or 0 when the
// path carries no line number (e.g. a structured JSON path like "$.a.b").
func lineFromPath(path string) int {
	m := lineRe.FindStringSubmatch(path)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// bareLinePathRe matches a path that is nothing but a "line:N" locator.
var bareLinePathRe = regexp.MustCompile(`^line:\d+$`)

// isBareLinePath reports whether path encodes only a line number, with no
// structural or section context — making it redundant with the Line field.
func isBareLinePath(path string) bool {
	return bareLinePathRe.MatchString(path)
}

func shouldSkipValue(value string, rule Rule, lang string) bool {
	return shouldIgnoreValue(value, rule) || isTemplatePlaceholder(value, lang) || isURLWithoutCredentials(value)
}

// templatePlaceholderRe matches the brace/paren-delimited variable and template
// placeholders whose presence anywhere in a value means it is a substitution
// target rather than a literal secret: ${VAR} and $(VAR) (shell, Make, CI),
// {{ var }} (Mustache/Jinja/Helm/Go templates). These delimiters are distinctive
// enough that a match anywhere in the value is a reliable signal.
var templatePlaceholderRe = regexp.MustCompile(`\$\{[^}]*\}|\$\([^)]*\)|\{\{[^}]*\}\}`)

// atVarPlaceholderRe matches a paired @VAR@ placeholder (Autotools/Maven resource
// filtering) anywhere in a value; atVarPlaceholderWholeRe requires it to be the
// entire value. The embedded form — e.g. inside a URL like
// http://@NAME_LOWER@-ws.example.net:20000, which substitutes to a credential-free
// host — is only honored for formats Maven filters by this delimiter (see
// langUsesAtFilter). Elsewhere a bare '@...@' run is more likely part of a real
// secret than a substitution target, so only a whole-value match counts.
var atVarPlaceholderRe = regexp.MustCompile(`@[A-Za-z0-9_.]+@`)
var atVarPlaceholderWholeRe = regexp.MustCompile(`^@[A-Za-z0-9_.]+@$`)

// pctVarPlaceholderRe matches a value that is, in its entirety, a single
// %-delimited placeholder such as %DB_HOST% (Windows batch, Maven filtering).
// Unlike '@', a single '%' also occurs inside ordinary secrets (URL-encoded
// passwords such as p%41ss%2Fword), so only a whole-value match is treated as a
// placeholder, not a substring one.
var pctVarPlaceholderRe = regexp.MustCompile(`^%[A-Za-z0-9_.]+%$`)

// langUsesAtFilter reports whether lang is a format where the paired @VAR@
// resource-filtering placeholder is conventional, so an embedded (not just
// whole-value) @VAR@ should be treated as a placeholder. Limited to the resource
// types Maven filters by the '@...@' delimiter.
func langUsesAtFilter(lang string) bool {
	return lang == "xml" || lang == "properties"
}

// isTemplatePlaceholder reports whether value is, or embeds, a variable/template
// placeholder — e.g. ${DB_HOST}, $(secret), {{ db_host }}, @DB_HOST@, or a
// whole-value %DB_HOST%. Such values defer the real secret to substitution time,
// so the literal text is not itself a credential and should not be flagged. The
// paired @VAR@ form is honored embedded only for lang formats that use '@...@'
// resource filtering (langUsesAtFilter); elsewhere it must be the whole value.
func isTemplatePlaceholder(value, lang string) bool {
	value = normalizeScalar(value)
	if templatePlaceholderRe.MatchString(value) || pctVarPlaceholderRe.MatchString(value) {
		return true
	}
	if langUsesAtFilter(lang) {
		return atVarPlaceholderRe.MatchString(value)
	}
	return atVarPlaceholderWholeRe.MatchString(value)
}

// nameSignalsSecret reports whether name indicates a secret under rule: it must
// match at least one of the rule's name patterns and not match any of its
// IgnoreNamePatterns. The ignore patterns let benign keys that happen to contain
// a trigger substring (e.g. "label" or "labelKey") be excluded.
func nameSignalsSecret(name string, rule Rule) bool {
	if !matchesAnyNameRegex(name, rule) {
		return false
	}

	for _, re := range rule.IgnoreNamePatterns {
		if re.MatchString(name) {
			return false
		}
	}

	return true
}

// matchesAnyNameRegex reports whether name matches any of the rule's compiled
// name patterns.
func matchesAnyNameRegex(name string, rule Rule) bool {
	for _, nr := range rule.NameRegexes {
		if nr.Regex.MatchString(name) {
			return true
		}
	}
	return false
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

func isLikelySecretValue(name, value string, rule Rule, lang string) bool {
	value = strings.TrimSpace(value)

	if value == "" {
		return false
	}

	// A value that merely restates its key name is a placeholder, not a real
	// credential: password="password", api_key="your-api-key", token="TOKEN".
	if valueEchoesName(name, value) {
		return false
	}

	// A value highly similar to its key name is a near-echo placeholder
	// (password="password1", secret="secrets", passwd="passw0rd"). Similarity is
	// the max of normalized Levenshtein and Jaro-Winkler, the latter rewarding the
	// shared prefixes typical of these fakes.
	if rule.MaxNameValueSimilarity > 0 && nameValueSimilarity(name, value) >= rule.MaxNameValueSimilarity {
		return false
	}

	if classifySecretReason(value) != "" {
		return true
	}

	if isTemplatePlaceholder(value, lang) {
		return false
	}

	if looksLikeNaturalLanguage(value) {
		return false
	}

	if len(value) < rule.MinValueLen {
		return false
	}

	// A secret-y key name alone isn't enough: a value with too little variety
	// (placeholders, repeated characters, simple words) reads as a non-secret.
	if rule.MinEntropy > 0 && shannonEntropy(normalizeScalar(value)) < rule.MinEntropy {
		return false
	}

	return !isStopword(value, rule)
}

// isStopword reports whether value is a known non-secret: as in gitleaks, it
// matches when the value contains (case-insensitively) any word from the built-in
// stopword set or any extra stopword configured on the rule.
func isStopword(value string, rule Rule) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	return containsStopword(lower, builtinStopwords) || containsStopword(lower, rule.Stopwords)
}

// fillerWords are the placeholder qualifiers that commonly wrap an echoed key
// name in a fake value, e.g. the "your" of api_key="your-api-key" or the "my" of
// secret="my-secret". Stripping them lets the value's core be compared to the
// name.
var fillerWords = map[string]bool{
	"your": true, "my": true, "the": true, "a": true, "an": true,
	"some": true, "example": true, "sample": true, "placeholder": true,
	"change": true, "changeme": true, "me": true, "real": true,
	"actual": true, "valid": true, "test": true, "testing": true,
	"dummy": true, "fake": true, "insert": true, "enter": true,
	"put": true, "here": true, "value": true, "goes": true,
	"todo": true, "fixme": true, "xxx": true, "default": true,
}

// valueEchoesName reports whether value is merely a restatement of the key name,
// optionally wrapped in placeholder filler words — the signature of an obvious
// fake credential rather than a real secret (password="password",
// api_key="your-api-key", token="TOKEN", secret="<my-secret>"). Comparison is
// word-based and case-insensitive and ignores separators and camelCase, so
// "apiKey" and "your-api-key" both reduce to "apikey".
func valueEchoesName(name, value string) bool {
	nameKey := strings.Join(identifierWords(name), "")
	if nameKey == "" {
		return false
	}

	var core []string
	for _, w := range identifierWords(value) {
		if !fillerWords[w] {
			core = append(core, w)
		}
	}
	if len(core) == 0 {
		return false
	}

	return strings.Join(core, "") == nameKey
}

// levenshtein returns the edit distance between a and b: the minimum number of
// single-rune insertions, deletions, or substitutions to turn one into the other.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)

	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}

	return prev[len(rb)]
}

// identifierWords splits an identifier into lowercase alphanumeric words,
// breaking on non-alphanumeric separators and camelCase boundaries, so "apiKey",
// "api_key", and "API-KEY" all yield comparable word lists.
func identifierWords(s string) []string {
	var words []string
	var cur []rune

	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}

	var prev rune
	for _, r := range s {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			// camelCase boundary: fooBar -> foo|Bar.
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()

	return words
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

// buildMeta assembles a finding's optional metadata from its value. It merges
// JWT claims/header, URL credentials, and connection-string fields into one Meta,
// returning nil when the value yields no metadata so non-matching findings carry
// no Meta. Correlation may further enrich the result later (see enrichMetaFromPartner).
func buildMeta(value string) *Meta {
	var meta Meta
	populated := false

	if jwt := parseJWT(value); jwt != nil {
		meta.JWT = jwt
		populated = true
	}

	if parseURLMeta(value, &meta) {
		populated = true
	}

	if parseConnStringMeta(value, &meta) {
		populated = true
	}

	if !populated {
		return nil
	}

	return &meta
}

// parseJWT extracts the header and claims from a JWT embedded in value. The
// standard iss/iat/exp claims are mapped to dedicated fields, the decoded header
// to Header, and every other claim to Extra. It returns nil when value contains
// no JWT, the token can't be decoded, or it carries no header and no claims.
func parseJWT(value string) *JWT {
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

	jwt := &JWT{}
	populated := false

	if header, err := decodeJWTSegment(parts[0]); err == nil {
		var h map[string]any
		if json.Unmarshal(header, &h) == nil && len(h) > 0 {
			jwt.Header = h
			populated = true
		}
	}

	for key, raw := range claims {
		switch key {
		case "iss":
			if s, ok := raw.(string); ok && s != "" {
				jwt.Issuer = s
				populated = true
			}
		case "iat":
			if n, ok := raw.(float64); ok && n != 0 {
				jwt.Iat = int64(n)
				populated = true
			}
		case "exp":
			if n, ok := raw.(float64); ok && n != 0 {
				jwt.Expiration = int64(n)
				jwt.IsExpired = jwt.Expiration < time.Now().Unix()
				populated = true
			}
		default:
			if jwt.Extra == nil {
				jwt.Extra = make(map[string]any, len(claims))
			}
			jwt.Extra[key] = raw
			populated = true
		}
	}

	if !populated {
		return nil
	}

	return jwt
}

// parseURLMeta fills Username, Host, and URL on meta when value is a URL carrying
// userinfo credentials (user:pass@host). It returns true when it set any field.
func parseURLMeta(value string, meta *Meta) bool {
	u, ok := parseURL(value)
	if !ok || u.User == nil {
		return false
	}

	if name := u.User.Username(); name != "" && meta.Username == "" {
		meta.Username = name
	}
	if u.Host != "" && meta.Host == "" {
		meta.Host = u.Host
	}
	if meta.URL == "" {
		meta.URL = normalizeScalar(value)
	}

	return true
}

// connStringFields maps a normalized connection-string key to the Meta field it
// populates. Keys are matched case-insensitively against the part before the
// `=`/`:` separator. The recognized keys mirror looksLikeConnectionString.
var connStringFields = []struct {
	keys  []string
	field func(*Meta) *string
}{
	{[]string{"username", "user id", "uid", "user"}, func(m *Meta) *string { return &m.Username }},
	{[]string{"data source", "server", "host"}, func(m *Meta) *string { return &m.Host }},
	{[]string{"client id", "clientid", "client_id", "appid"}, func(m *Meta) *string { return &m.ClientID }},
	{[]string{"client secret", "clientsecret", "client_key"}, func(m *Meta) *string { return &m.ClientKey }},
}

// parseConnStringMeta fills Username, Host, ClientID, and ClientKey on meta from a
// `key=value;`/`key: value` connection string. It returns true when it set any
// field. Only connection-string-shaped values are inspected.
func parseConnStringMeta(value string, meta *Meta) bool {
	if !looksLikeConnectionString(value) {
		return false
	}

	set := false
	for _, pair := range strings.FieldsFunc(value, func(r rune) bool { return r == ';' }) {
		key, val, ok := splitConnStringPair(pair)
		if !ok {
			continue
		}

		for _, f := range connStringFields {
			if !containsFold(f.keys, key) {
				continue
			}
			if dst := f.field(meta); *dst == "" {
				*dst = val
				set = true
			}
			break
		}
	}

	return set
}

// splitConnStringPair splits a single connection-string pair into a normalized
// (lowercased, trimmed) key and its raw value, accepting either `=` or `:` as the
// separator. ok is false when the pair has no separator or an empty key.
func splitConnStringPair(pair string) (key, val string, ok bool) {
	idx := strings.IndexAny(pair, "=:")
	if idx < 0 {
		return "", "", false
	}

	key = strings.ToLower(strings.TrimSpace(pair[:idx]))
	val = strings.TrimSpace(pair[idx+1:])
	if key == "" {
		return "", "", false
	}

	return key, val, true
}

// containsFold reports whether s equals any of keys (already lowercase).
func containsFold(keys []string, s string) bool {
	for _, k := range keys {
		if k == s {
			return true
		}
	}
	return false
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
