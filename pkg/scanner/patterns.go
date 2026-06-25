package scanner

import (
	"fmt"
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

// ExaminationFocus bundles the single item under inspection for value-pattern
// detection: where it lives (File/Path), how it is labelled (Name), its scalar
// Value, and a snapshot of the most-recent prior findings for this file, kept
// for correlation context.
type ExaminationFocus struct {
	File         string
	Path         string
	Name         string
	Value        string
	PrevFindings []Finding
}

// minPrevWindow is the floor for how many recent findings are carried as
// correlation context; the effective window grows to fit the largest correlation
// rule (see RuleSet.prevWindow).
const minPrevWindow = 3

// recentFindings returns the up-to-n most recent findings, in append order, used
// to seed an ExaminationFocus.PrevFindings without carrying the whole slice.
func recentFindings(findings []Finding, n int) []Finding {
	if n <= 0 || len(findings) <= n {
		return findings
	}
	return findings[len(findings)-n:]
}

// detectValuePatterns scans a single value against the built-in gitleaks
// patterns and any configured custom (trufflehog-style) detectors, independent
// of the key name. It honors the configured value-ignore prefixes/patterns (so
// suppressions still apply) and emits at most one finding. The built-in patterns
// take precedence and are tagged "gitleaks:<rule-id>"; a custom detector match
// is tagged "custom:<detector-name>".
func detectValuePatterns(focus ExaminationFocus, set RuleSet) []Finding {
	value := normalizeScalar(focus.Value)
	if value == "" {
		return nil
	}

	if valueSuppressed(value, set.Rules) {
		return nil
	}

	if id := matchValuePattern(value); id != "" {
		return []Finding{newFinding(
			focus.File,
			focus.Path,
			"value_pattern",
			"value_pattern",
			focus.Name,
			value,
			"gitleaks:"+id,
		)}
	}

	for _, d := range set.Detectors {
		if _, ok := d.match(value, focus.Name); ok {
			return []Finding{newFinding(
				focus.File,
				focus.Path,
				"value_pattern",
				"value_pattern",
				focus.Name,
				value,
				"custom:"+d.Name,
			)}
		}
	}

	if reason := matchHighEntropy(value, set.Rules); reason != "" {
		return []Finding{newFinding(
			focus.File,
			focus.Path,
			"value_pattern",
			"value_pattern",
			focus.Name,
			value,
			reason,
		)}
	}

	return nil
}

// maxHighEntropyLen bounds the generic high-entropy detector to token-sized
// values. Real opaque secrets are short; long strings with many distinct symbols
// (source code, regexes, JSON blobs, prose) have naturally high per-symbol
// entropy and would otherwise be flagged wholesale.
const maxHighEntropyLen = 200

// matchHighEntropy reports a finding reason when value's Shannon entropy meets a
// rule's configured high_entropy_threshold, flagging opaque, high-randomness
// strings whose key name gives no hint they are secret. It restricts itself to
// single token-like values (no whitespace, bounded length, not natural language)
// so source code and prose don't trip the threshold, and embeds the measured
// entropy in the reason (e.g. "high_entropy:4.73"). The first rule with a
// threshold the value clears wins.
func matchHighEntropy(value string, rules []Rule) string {
	value = normalizeScalar(value)
	if value == "" {
		return ""
	}

	// A genuine opaque token is one whitespace-free run of bounded length; longer
	// or space-bearing values are code/prose whose entropy means nothing here.
	if len(value) > maxHighEntropyLen || strings.ContainsAny(value, " \t\r\n") {
		return ""
	}

	for _, rule := range rules {
		if rule.HighEntropyThreshold <= 0 {
			continue
		}
		if len(value) < rule.MinValueLen {
			continue
		}
		if looksLikeNaturalLanguage(value) {
			continue
		}

		if e := shannonEntropy(value); e >= rule.HighEntropyThreshold {
			return fmt.Sprintf("high_entropy:%.2f", e)
		}
	}

	return ""
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
