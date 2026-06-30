// Command patterns derives value-shape secret patterns from a gitleaks config
// (gitleaks.toml) and emits a generated Go source file for package scanner.
//
// Gitleaks gets its precision from four things that the scanner's value-only
// ValuePattern model does not have: a per-rule keyword pre-filter, a per-rule
// entropy threshold, secret-group extraction, and per-rule allowlists. Loading
// every rule as a bare regexp.MatchString would therefore regress precision
// badly. This generator keeps only the rules that are safe to match against an
// already-extracted value: those whose regex carries a distinctive *fixed token
// prefix* (e.g. ghp_, glpat-, ABSK), which is what makes a vendor token
// self-identifying without surrounding key/quote context. Generic, key-context,
// and short-prefix rules are dropped.
//
// IDs already curated by hand in patterns.go are excluded so the hand-tuned
// versions win and nothing is double-listed. Per-rule allowlist regexes that
// target the secret/match (not the file path or whole line, which value-only
// matching cannot see) are carried through so example keys still suppress.
//
// Regenerate with: go generate ./pkg/scanner
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	in := flag.String("in", "../../gitleaks.toml", "path to gitleaks.toml")
	out := flag.String("out", "patterns_gitleaks_gen.go", "generated Go output path")
	curated := flag.String("curated", "patterns.go", "existing hand-curated patterns file, parsed to skip duplicate IDs")
	minPrefix := flag.Int("min-prefix", 3, "minimum fixed-literal token prefix length")
	flag.Parse()

	src, err := os.ReadFile(*in)
	if err != nil {
		fatal("read %s: %v", *in, err)
	}
	curatedSrc, err := os.ReadFile(*curated)
	if err != nil {
		fatal("read %s: %v", *curated, err)
	}

	rules := parseRules(string(src))
	skip := curatedIDs(string(curatedSrc))

	var kept []rule
	stats := map[string]int{}
	for i := range rules {
		r := &rules[i]
		if skip[r.id] {
			stats["curated"]++
			continue
		}
		why := admit(r, *minPrefix)
		if why != "" {
			stats[why]++
			continue
		}
		kept = append(kept, *r)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].id < kept[j].id })

	code, err := render(*in, kept)
	if err != nil {
		fatal("render: %v", err)
	}
	if err := os.WriteFile(*out, code, 0o644); err != nil {
		fatal("write %s: %v", *out, err)
	}

	fmt.Fprintf(os.Stderr, "gitleaks rules: %d total, %d already curated, %d generated\n", len(rules), stats["curated"], len(kept))
	fmt.Fprintf(os.Stderr, "skipped: %s\n", fmtStats(stats))
	for _, r := range kept {
		fmt.Fprintf(os.Stderr, "  + %-40s prefix=%q\n", r.id, r.prefix)
	}
}

// rule is one parsed [[rules]] block, with the allowlist regexes that apply to
// value-only matching and the fixed prefix discovered by admit.
type rule struct {
	id         string
	regex      string
	entropy    float64
	allowlists []allowlist // raw allowlist blocks collected while parsing
	allow      []string    // lifted allowlist regexes targeting the secret/match
	prefix     string      // set by admit for reporting
}

// admit reports why a rule is rejected for value-only matching, or "" if it is
// kept. A rule is kept when its regex begins with a distinctive fixed token
// prefix and the whole regex compiles under RE2.
func admit(r *rule, minPrefix int) string {
	// Rules whose ID ends in "regex" are meta/config rules, not self-identifying
	// token rules, so they do not belong in value-shape matching.
	if strings.HasSuffix(r.id, "regex") {
		return "name-ends-regex"
	}
	if r.regex == "" {
		return "no-regex"
	}
	if _, err := regexp.Compile(r.regex); err != nil {
		return "uncompilable"
	}
	for _, a := range r.allow {
		if _, err := regexp.Compile(a); err != nil {
			return "bad-allowlist"
		}
	}

	p := leadingLiteral(r.regex)
	r.prefix = p
	if p == "" {
		return "no-fixed-prefix"
	}
	if genericKeyWord[strings.ToLower(p)] {
		return "generic-keyword-prefix"
	}
	distinctive := len(p) >= minPrefix || (len(p) >= 3 && strings.ContainsAny(p, "0123456789_-"))
	if !distinctive {
		return "prefix-too-short"
	}
	return ""
}

// leadingLiteral returns the fixed literal characters at the start of the token
// a regex matches, after stripping inline flags, a leading word boundary/anchor,
// and a single opening group. It stops at the first regex metacharacter, so for
// `\b((?:A3T[A-Z0-9]|AKIA|...)...)` it returns "A3T" and for `\bghp_[0-9a-zA-Z]{36}\b`
// it returns "ghp_". A regex that opens with a character class, a flag-then-class,
// or an optional context run (the key-context rules) yields "".
func leadingLiteral(re string) string {
	// Strip a leading inline-flags group, e.g. (?i) or (?is).
	if m := inlineFlags.FindString(re); m != "" {
		re = re[len(m):]
	}
	// Strip leading anchors / word boundaries.
	for {
		switch {
		case strings.HasPrefix(re, `\b`), strings.HasPrefix(re, `\A`):
			re = re[2:]
		case strings.HasPrefix(re, `^`):
			re = re[1:]
		default:
			goto groups
		}
	}
groups:
	// Strip leading group openers (one or more): a capture group `(`, a
	// non-capturing `(?:`, or a named group, each of which just wraps the token.
	for {
		switch {
		case strings.HasPrefix(re, `(?:`):
			re = re[3:]
		case namedGroupOpen.MatchString(re):
			re = re[len(namedGroupOpen.FindString(re)):]
		case strings.HasPrefix(re, `(`):
			re = re[1:]
		default:
			goto literal
		}
	}
literal:
	var b strings.Builder
	for i := 0; i < len(re); i++ {
		c := re[i]
		if isLiteralByte(c) {
			b.WriteByte(c)
			continue
		}
		break
	}
	return b.String()
}

// isLiteralByte reports whether c is a plain token character (not a regex
// metacharacter). Only these extend a fixed prefix.
func isLiteralByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '_', c == '-':
		return true
	}
	return false
}

var (
	inlineFlags    = regexp.MustCompile(`^\(\?[ismU]+\)`)
	namedGroupOpen = regexp.MustCompile(`^\(\?P?<[^>]+>`)
)

// genericKeyWord are leading literals that come from a rule's surrounding
// key-name context rather than a distinctive token, so a prefix equal to one of
// them means the rule is a generic key-context rule, not a self-identifying token.
var genericKeyWord = map[string]bool{
	"key": true, "api": true, "apikey": true, "secret": true, "token": true,
	"password": true, "passwd": true, "pass": true, "auth": true, "access": true,
	"client": true, "private": true, "public": true, "bearer": true, "credential": true,
	"credentials": true, "session": true, "oauth": true, "sk": true, "pk": true,
	// curl-* rules match a whole `curl ... -H/-u ...` command line, not a
	// self-identifying value, so they do not belong in value-shape matching.
	"curl": true,
}

// --- gitleaks.toml parsing -------------------------------------------------
//
// The file is auto-generated with a stable, regular shape (every regex is a
// single-line triple-quoted string), so a focused line parser is reliable and
// avoids adding a TOML dependency to the module.

func parseRules(src string) []rule {
	var rules []rule
	var cur *rule
	var allow *allowlist
	flush := func() {
		if cur != nil {
			rules = append(rules, *cur)
		}
		cur, allow = nil, nil
	}

	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		switch {
		case line == "[[rules]]":
			flush()
			cur = &rule{}
			allow = nil
			continue
		case line == "[[rules.allowlists]]":
			if cur != nil {
				cur.allowlists = append(cur.allowlists, allowlist{})
				allow = &cur.allowlists[len(cur.allowlists)-1]
			}
			continue
		case strings.HasPrefix(line, "[["), strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") && !strings.Contains(line, "="):
			// Any other table header (e.g. top-level [allowlist]) ends the rule.
			flush()
			continue
		}
		if cur == nil {
			continue
		}

		key, val, ok := splitKV(line)
		if !ok {
			continue
		}
		// An array value may span multiple lines: accumulate until the closing ].
		if strings.HasPrefix(val, "[") && !strings.HasSuffix(strings.TrimSpace(val), "]") {
			var sb strings.Builder
			sb.WriteString(val)
			for i+1 < len(lines) {
				i++
				sb.WriteString("\n")
				sb.WriteString(lines[i])
				if strings.Contains(lines[i], "]") {
					break
				}
			}
			val = sb.String()
		}

		switch key {
		case "id":
			cur.id = unquoteScalar(val)
		case "regex":
			if allow == nil {
				cur.regex = unquoteScalar(val)
			}
		case "entropy":
			cur.entropy, _ = strconv.ParseFloat(strings.TrimSpace(val), 64)
		case "regexTarget":
			if allow != nil {
				allow.target = unquoteScalar(val)
			}
		case "regexes":
			if allow != nil {
				allow.regexes = parseArray(val)
			}
		}
	}
	flush()

	// Lift the allowlist regexes that value-only matching can honor onto the rule.
	for i := range rules {
		for _, a := range rules[i].allowlists {
			// Default regexTarget is "secret"; "match" targets the matched token,
			// which for an extracted value is effectively the same. "line"/"" path
			// targets need context we do not have, so they are skipped.
			if a.target == "" || a.target == "secret" || a.target == "match" {
				rules[i].allow = append(rules[i].allow, a.regexes...)
			}
		}
	}
	return rules
}

type allowlist struct {
	target  string
	regexes []string
}

func splitKV(line string) (key, val string, ok bool) {
	i := strings.Index(line, "=")
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	val = strings.TrimSpace(line[i+1:])
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, val, true
}

// unquoteScalar strips a triple-quoted (”'...”'), double-quoted, or
// single-quoted TOML scalar down to its contents.
func unquoteScalar(s string) string {
	s = strings.TrimSpace(s)
	for _, q := range []string{"'''", `"""`} {
		if strings.HasPrefix(s, q) && strings.HasSuffix(s, q) && len(s) >= 2*len(q) {
			return s[len(q) : len(s)-len(q)]
		}
	}
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		inner := s[1 : len(s)-1]
		if s[0] == '"' {
			if uq, err := strconv.Unquote(s); err == nil {
				return uq
			}
		}
		return inner
	}
	return s
}

// parseArray extracts every quoted element from a (possibly multi-line) TOML
// array literal.
func parseArray(s string) []string {
	var out []string
	for _, m := range arrayElem.FindAllStringSubmatch(s, -1) {
		switch {
		case m[1] != "":
			out = append(out, m[1])
		case m[2] != "":
			out = append(out, m[2])
		case m[3] != "":
			out = append(out, m[3])
		}
	}
	return out
}

// arrayElem matches one array element: ”'...”', "...", or '...'.
var arrayElem = regexp.MustCompile(`'''((?:[^']|'[^']|''[^'])*)'''|"((?:[^"\\]|\\.)*)"|'([^']*)'`)

// curatedIDs returns the set of gitleaks rule IDs already present in the
// hand-curated patterns file, so they are not duplicated by generation.
func curatedIDs(src string) map[string]bool {
	ids := map[string]bool{}
	for _, m := range curatedEntry.FindAllStringSubmatch(src, -1) {
		ids[m[1]] = true
	}
	return ids
}

// curatedEntry matches a `{ID: "rule-id", Regex: regexp.MustCompile(` entry.
var curatedEntry = regexp.MustCompile(`\{ID:\s*"([a-z0-9][a-z0-9-]*)",\s*Regex:`)

func render(srcPath string, rules []rule) ([]byte, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "// Code generated by cmd/generate/patterns from %s. DO NOT EDIT.\n", srcPath)
	b.WriteString("\npackage scanner\n\nimport \"regexp\"\n\n")
	b.WriteString("// gitleaksGeneratedPatterns are value-shape secret patterns auto-derived from\n")
	b.WriteString("// gitleaks.toml, filtered to rules whose regex has a distinctive fixed token\n")
	b.WriteString("// prefix and so are safe to match against an extracted value without the\n")
	b.WriteString("// keyword/entropy/context gating gitleaks applies. IDs hand-curated in\n")
	b.WriteString("// patterns.go are excluded and take precedence. Regenerate with:\n")
	b.WriteString("//\tgo generate ./pkg/scanner\n")
	b.WriteString("var gitleaksGeneratedPatterns = []ValuePattern{\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "\t{ID: %s, Regex: regexp.MustCompile(%s)", goRaw(r.id), goRaw(r.regex))
		if len(r.allow) > 0 {
			b.WriteString(", Allow: []*regexp.Regexp{")
			for i, a := range r.allow {
				if i > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, "regexp.MustCompile(%s)", goRaw(a))
			}
			b.WriteString("}")
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n")
	return format.Source(b.Bytes())
}

// goRaw renders s as a Go raw string literal when it contains no backtick,
// otherwise as a double-quoted literal. gitleaks regexes use backslashes
// liberally, so raw literals keep them readable.
func goRaw(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	return strconv.Quote(s)
}

func fmtStats(m map[string]int) string {
	var parts []string
	for k, v := range m {
		if k == "curated" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " ")
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "patterns: "+format+"\n", a...)
	os.Exit(1)
}
