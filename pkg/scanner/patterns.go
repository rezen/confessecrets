package scanner

import (
	"regexp"
	"strings"
)

// ValuePattern is a gitleaks-style rule that recognizes a secret by the shape of
// the value itself, independent of any surrounding key name.
type ValuePattern struct {
	ID    string
	Regex *regexp.Regexp
}

// gitleaksPatterns are high-confidence, self-identifying secret token patterns
// adapted from gitleaks (github.com/gitleaks/gitleaks, cmd/generate/config/rules).
//
// They are adjusted for Go's RE2 engine and for matching values that have
// already been extracted from their keys: the raw-text leading/trailing context
// and capture groups used in the upstream rules are dropped, keeping the core
// token shape. Keyword-gated rules that rely on surrounding prose (e.g. heroku,
// telegram) are intentionally omitted because they would match bare UUIDs here.
var gitleaksPatterns = []ValuePattern{
	{"aws-access-token", regexp.MustCompile(`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b`)},
	{"github-pat", regexp.MustCompile(`\bghp_[0-9a-zA-Z]{36}\b`)},
	{"github-fine-grained-pat", regexp.MustCompile(`\bgithub_pat_\w{82}\b`)},
	{"github-oauth", regexp.MustCompile(`\bgho_[0-9a-zA-Z]{36}\b`)},
	{"github-app-token", regexp.MustCompile(`\b(?:ghu|ghs)_[0-9a-zA-Z]{36}\b`)},
	{"gitlab-pat", regexp.MustCompile(`\bglpat-[\w-]{20}\b`)},
	{"slack-bot-token", regexp.MustCompile(`xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)},
	{"slack-user-token", regexp.MustCompile(`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`)},
	{"stripe-access-token", regexp.MustCompile(`\b(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}\b`)},
	{"sendgrid-api-token", regexp.MustCompile(`\bSG\.[A-Za-z0-9=_.\-]{66}`)},
	{"twilio-api-key", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	{"npm-access-token", regexp.MustCompile(`\bnpm_[a-zA-Z0-9]{36}\b`)},
	{"pypi-upload-token", regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`)},
	{"openai-api-key", regexp.MustCompile(`\b(?:sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b`)},
	{"anthropic-api-key", regexp.MustCompile(`\bsk-ant-api03-[a-zA-Z0-9_\-]{93}AA\b`)},
	{"gcp-api-key", regexp.MustCompile(`\bAIza[\w-]{35}\b`)},
	{"jwt", regexp.MustCompile(`\bey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9/\\_-]{17,}\.(?:[a-zA-Z0-9/\\_-]{10,}={0,2})?`)},
	{"private-key", regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`)},
	{"square-access-token", regexp.MustCompile(`\b(?:EAAA|sq0atp-)[\w-]{22,60}\b`)},
	{"shopify-shared-secret", regexp.MustCompile(`\bshpss_[a-fA-F0-9]{32}\b`)},
}

// matchValuePattern returns the ID of the first gitleaks pattern whose regex
// matches value, or "" if none match.
func matchValuePattern(value string) string {
	for _, p := range gitleaksPatterns {
		if p.Regex.MatchString(value) {
			return p.ID
		}
	}

	return ""
}

// detectValuePatterns scans a single value against the gitleaks patterns,
// independent of the key name. It honors the configured value-ignore
// prefixes/patterns (so suppressions still apply) and emits at most one finding,
// tagged with reason "gitleaks:<rule-id>".
func detectValuePatterns(file, path, name, value string, rules []Rule) []Finding {
	value = normalizeScalar(value)
	if value == "" {
		return nil
	}

	if valueSuppressed(value, rules) {
		return nil
	}

	id := matchValuePattern(value)
	if id == "" {
		return nil
	}

	return []Finding{newFinding(
		file,
		path,
		"value_pattern",
		"value_pattern",
		name,
		value,
		"gitleaks:"+id,
	)}
}

// valueSuppressed reports whether value is excluded by any rule's ignore
// prefixes or patterns. Unlike shouldSkipValue it does not treat plain URLs as
// skippable, since a tokenized secret can legitimately live inside a URL.
func valueSuppressed(value string, rules []Rule) bool {
	for _, rule := range rules {
		if shouldIgnoreValue(value, rule) {
			return true
		}
	}

	return false
}

// lastSegment returns the trailing key of a dotted JSON-ish path (e.g. the
// "password" of "$.db.password"), used as the finding name for raw values
// surfaced by value scanning.
func lastSegment(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}

	return path
}
