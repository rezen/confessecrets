package scanner

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	ts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// envLookupRe matches the callee of an environment/config lookup that takes a
// fallback/default argument (e.g. os.getenv, os.environ.get, System.getenv,
// getOrDefault, GetEnvironmentVariable, config.GetValue). It is matched against
// the call's full callee text, so receiver-qualified names are covered.
var envLookupRe = regexp.MustCompile(`(?i)(getenv|environ|lookupenv|getproperty|getordefault|getvalue|getconfig|getsecret|env[_-]?(default|var|value)|fromenv)`)

// envRefRe matches the left-hand side of a logical-default expression
// (X || "..." / X ?? "..." / X or "...") when X reads from the environment or
// configuration, e.g. process.env.KEY, os.getenv("KEY"), Environment.GetEnvironmentVariable(...).
var envRefRe = regexp.MustCompile(`(?i)(getenv|environ|process\.env|getenvironmentvariable|lookupenv|config(uration)?\[)`)

// defaultOperators are the operators that introduce a fallback value: logical-OR
// and null-coalescing (C#/JS) and Python's boolean `or`. Matching the operator
// (read from the AST) is what separates a real default from a comparison such as
// `process.env.MODE == "prod"`.
var defaultOperators = map[string]bool{"||": true, "??": true, "or": true}

// quotedKeyRe extracts a quoted key from a lookup expression, e.g. the
// "DB_PASSWORD" of os.getenv("DB_PASSWORD").
var quotedKeyRe = regexp.MustCompile(`["` + "`" + `']([^"` + "`" + `']+)["` + "`" + `']`)

// envNameFromLookup derives a representative key name from a lookup expression:
// the quoted key if present (getenv("DB_PASSWORD")), otherwise the trailing
// member segment (process.env.DB_PASSWORD).
func envNameFromLookup(text string) string {
	if m := quotedKeyRe.FindStringSubmatch(text); m != nil {
		return m[1]
	}

	text = strings.TrimSpace(text)
	if i := strings.LastIndexAny(text, ".["); i >= 0 {
		text = text[i+1:]
	}
	return strings.Trim(text, "[]\"'` ")
}

// looksLikeArgSecret is a stricter gate used when a secret value is passed as a
// call argument or a default, where benign prose (prompts, labels, format
// strings) is common. It accepts a value only if it carries a recognized secret
// reason, or it passes the standard secret heuristics AND contains no whitespace
// — real opaque tokens rarely do, while prompts like "Password: " do.
func looksLikeArgSecret(name, value string, rule Rule) bool {
	if classifySecretReason(value) != "" {
		return true
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	return isLikelySecretValue(name, value, rule)
}

// SourceDetector scans general-purpose source code (Python, JavaScript,
// TypeScript, Go, Java, C#) for hardcoded secrets using tree-sitter. Unlike the
// structured-config detectors, it distinguishes a secret *literal* from a runtime
// lookup: it flags `password = "hunter2"` (the value node is a string literal)
// but not `password = os.environ.get("SECRET")` (the value node is a call), which
// regex-only scanners get wrong.
//
// Parsing uses a pure-Go tree-sitter runtime with the grammars embedded in the
// binary (github.com/odvcencio/gotreesitter), so there is nothing to install,
// download, or compile at runtime, and the build stays CGO-free and
// cross-compilable.
type SourceDetector struct{}

func (SourceDetector) Detect(file string, data []byte, set RuleSet) []Finding {
	spec := sourceLangForExt(strings.ToLower(filepath.Ext(file)))
	if spec == nil {
		return nil
	}

	loaded := defaultSourceEngine.langFor(spec)
	if loaded == nil {
		return nil
	}

	return loaded.detect(file, data, set)
}

// sourceLang describes one language's grammar and the tree-sitter queries used to
// extract name/value assignments and bare string literals from its source.
type sourceLang struct {
	name string              // identifier used for caching/diagnostics
	lang func() *ts.Language // embedded grammar accessor
	exts []string            // file extensions handled, lowercase incl. dot

	// pairQuery captures @name and @value, where @value is constrained to string
	// literal node kinds so call/identifier right-hand sides never match.
	pairQuery string

	// valueQuery captures @value over every string literal, for value-shape
	// (gitleaks-style) scanning regardless of the surrounding name.
	valueQuery string

	// envQuery captures @fn (the callee), @envname (the first string argument,
	// typically the env var / config key), and @value (the second string
	// argument, the fallback/default) of a two-string call. It is used to flag a
	// hardcoded fallback secret behind an env lookup, e.g.
	// os.getenv("DB_PASSWORD", "hunter2"). Empty disables this pass.
	envQuery string

	// callArgQuery captures @name (the assignment target) and @value (a string
	// literal argument of the right-hand call). It flags a secret passed into any
	// call when the assignment target signals a secret, e.g.
	// password = vault.fetch("key", "s3cr3t!"). Empty disables this pass.
	callArgQuery string

	// logicalQuery captures @lookup (the left operand), @value (a string literal
	// right operand), and @expr (the whole expression, so the operator can be
	// read). It flags a hardcoded default behind a logical-OR / null-coalescing
	// env read, e.g. process.env.KEY || "fallback". Empty disables this pass.
	logicalQuery string
}

// sourceLangs is the language registry. The queries are validated end-to-end
// against the embedded grammars by the test suite; if one ever fails to compile
// against a grammar, that language is disabled without affecting the others.
var sourceLangs = []*sourceLang{
	{
		name: "python",
		lang: grammars.PythonLanguage,
		exts: []string{".py", ".pyi"},
		pairQuery: `
(assignment left: (identifier) @name right: (string) @value)
(keyword_argument name: (identifier) @name value: (string) @value)
(pair key: (string) @name value: (string) @value)
`,
		valueQuery:   `(string) @value`,
		envQuery:     `(call function: (_) @fn arguments: (argument_list (string) @envname (string) @value))`,
		callArgQuery: `(assignment left: (identifier) @name right: (call function: (_) @fn arguments: (argument_list (string) @value)))`,
		logicalQuery: `(boolean_operator left: (_) @lookup right: (string) @value) @expr`,
	},
	{
		name: "javascript",
		lang: grammars.JavascriptLanguage,
		exts: []string{".js", ".jsx", ".cjs", ".mjs"},
		pairQuery: `
(variable_declarator name: (identifier) @name value: (string) @value)
(assignment_expression left: (identifier) @name right: (string) @value)
(assignment_expression left: (member_expression property: (property_identifier) @name) right: (string) @value)
(pair key: (property_identifier) @name value: (string) @value)
(pair key: (string) @name value: (string) @value)
`,
		valueQuery: `(string) @value`,
		envQuery:   `(call_expression function: (_) @fn arguments: (arguments (string) @envname (string) @value))`,
		callArgQuery: `
(variable_declarator name: (identifier) @name value: (call_expression function: (_) @fn arguments: (arguments (string) @value)))
(assignment_expression left: (identifier) @name right: (call_expression function: (_) @fn arguments: (arguments (string) @value)))
`,
		logicalQuery: `(binary_expression left: (_) @lookup right: (string) @value) @expr`,
	},
	{
		name: "typescript",
		lang: grammars.TypescriptLanguage,
		exts: []string{".ts", ".tsx", ".mts", ".cts"},
		pairQuery: `
(variable_declarator name: (identifier) @name value: (string) @value)
(assignment_expression left: (identifier) @name right: (string) @value)
(assignment_expression left: (member_expression property: (property_identifier) @name) right: (string) @value)
(pair key: (property_identifier) @name value: (string) @value)
(pair key: (string) @name value: (string) @value)
`,
		valueQuery: `(string) @value`,
		envQuery:   `(call_expression function: (_) @fn arguments: (arguments (string) @envname (string) @value))`,
		callArgQuery: `
(variable_declarator name: (identifier) @name value: (call_expression function: (_) @fn arguments: (arguments (string) @value)))
(assignment_expression left: (identifier) @name right: (call_expression function: (_) @fn arguments: (arguments (string) @value)))
`,
		logicalQuery: `(binary_expression left: (_) @lookup right: (string) @value) @expr`,
	},
	{
		name: "go",
		lang: grammars.GoLanguage,
		exts: []string{".go"},
		pairQuery: `
(short_var_declaration left: (expression_list (identifier) @name) right: (expression_list (interpreted_string_literal) @value))
(assignment_statement left: (expression_list (identifier) @name) right: (expression_list (interpreted_string_literal) @value))
(const_spec name: (identifier) @name value: (expression_list (interpreted_string_literal) @value))
(var_spec name: (identifier) @name value: (expression_list (interpreted_string_literal) @value))
(keyed_element (literal_element (identifier) @name) (literal_element (interpreted_string_literal) @value))
`,
		valueQuery: `(interpreted_string_literal) @value (raw_string_literal) @value`,
		envQuery:   `(call_expression function: (_) @fn arguments: (argument_list (interpreted_string_literal) @envname (interpreted_string_literal) @value))`,
		callArgQuery: `
(short_var_declaration left: (expression_list (identifier) @name) right: (expression_list (call_expression function: (_) @fn arguments: (argument_list (interpreted_string_literal) @value))))
(assignment_statement left: (expression_list (identifier) @name) right: (expression_list (call_expression function: (_) @fn arguments: (argument_list (interpreted_string_literal) @value))))
(var_spec name: (identifier) @name value: (expression_list (call_expression function: (_) @fn arguments: (argument_list (interpreted_string_literal) @value))))
(const_spec name: (identifier) @name value: (expression_list (call_expression function: (_) @fn arguments: (argument_list (interpreted_string_literal) @value))))
`,
	},
	{
		name: "java",
		lang: grammars.JavaLanguage,
		exts: []string{".java"},
		pairQuery: `
(variable_declarator name: (identifier) @name value: (string_literal) @value)
(assignment_expression left: (identifier) @name right: (string_literal) @value)
`,
		valueQuery: `(string_literal) @value`,
		envQuery:   `(method_invocation name: (identifier) @fn arguments: (argument_list (string_literal) @envname (string_literal) @value))`,
		callArgQuery: `
(variable_declarator name: (identifier) @name value: (method_invocation name: (identifier) @fn arguments: (argument_list (string_literal) @value)))
(assignment_expression left: (identifier) @name right: (method_invocation name: (identifier) @fn arguments: (argument_list (string_literal) @value)))
`,
	},
	{
		name: "c_sharp",
		lang: grammars.CSharpLanguage,
		exts: []string{".cs"},
		pairQuery: `
(variable_declarator (identifier) @name (string_literal) @value)
(variable_declarator (identifier) @name (verbatim_string_literal) @value)
(assignment_expression left: (identifier) @name right: (string_literal) @value)
`,
		valueQuery: `(string_literal) @value (verbatim_string_literal) @value`,
		envQuery:   `(invocation_expression function: (_) @fn arguments: (argument_list (argument (string_literal) @envname) (argument (string_literal) @value)))`,
		callArgQuery: `
(variable_declarator (identifier) @name (invocation_expression function: (_) @fn arguments: (argument_list (argument (string_literal) @value))))
(assignment_expression left: (identifier) @name right: (invocation_expression function: (_) @fn arguments: (argument_list (argument (string_literal) @value))))
`,
		logicalQuery: `(binary_expression left: (_) @lookup right: (string_literal) @value) @expr`,
	},
}

// IsSourceFile reports whether path is a source-code file handled by the
// tree-sitter SourceDetector (as opposed to a structured-config format). It lets
// callers include or exclude source scanning by file.
func IsSourceFile(path string) bool {
	return sourceLangForExt(strings.ToLower(filepath.Ext(path))) != nil
}

func sourceLangForExt(ext string) *sourceLang {
	for _, l := range sourceLangs {
		for _, e := range l.exts {
			if e == ext {
				return l
			}
		}
	}
	return nil
}

// defaultSourceEngine is the process-wide tree-sitter engine. It loads each
// grammar and compiles its queries once, then caches them across files.
var defaultSourceEngine = &sourceEngine{loaded: map[string]*loadedLang{}}

type sourceEngine struct {
	mu     sync.Mutex
	loaded map[string]*loadedLang
}

type loadedLang struct {
	spec     *sourceLang
	lang     *ts.Language
	pairQ    *ts.Query
	valueQ   *ts.Query
	envQ     *ts.Query // nil when absent or failed to compile
	callArgQ *ts.Query // nil when absent or failed to compile
	logicalQ *ts.Query // nil when absent or failed to compile
}

// langFor returns the loaded grammar+queries for spec, compiling them on first
// use. It returns nil (and remembers the failure) only if a query fails to
// compile against the grammar, disabling that one language.
func (e *sourceEngine) langFor(spec *sourceLang) *loadedLang {
	e.mu.Lock()
	defer e.mu.Unlock()

	if cached, ok := e.loaded[spec.name]; ok {
		return cached // may be nil: a prior compile failed and is remembered.
	}

	loaded := buildLoadedLang(spec)
	e.loaded[spec.name] = loaded
	return loaded
}

func buildLoadedLang(spec *sourceLang) *loadedLang {
	lang := spec.lang()
	if lang == nil {
		return nil
	}

	pairQ, err := ts.NewQuery(spec.pairQuery, lang)
	if err != nil {
		return nil
	}

	valueQ, err := ts.NewQuery(spec.valueQuery, lang)
	if err != nil {
		return nil
	}

	// The supplementary queries are optional: if one is absent or fails to
	// compile against this grammar, that one pass is disabled rather than the
	// whole language.
	return &loadedLang{
		spec:     spec,
		lang:     lang,
		pairQ:    pairQ,
		valueQ:   valueQ,
		envQ:     optionalQuery(lang, spec.envQuery),
		callArgQ: optionalQuery(lang, spec.callArgQuery),
		logicalQ: optionalQuery(lang, spec.logicalQuery),
	}
}

// optionalQuery compiles an optional query, returning nil if it is empty or
// fails to compile.
func optionalQuery(lang *ts.Language, query string) *ts.Query {
	if query == "" {
		return nil
	}
	q, err := ts.NewQuery(query, lang)
	if err != nil {
		return nil
	}
	return q
}

// detect parses data once and runs both the name-driven and value-driven queries
// over the resulting tree.
func (l *loadedLang) detect(file string, data []byte, set RuleSet) []Finding {
	parser := ts.NewParser(l.lang)
	tree, err := parser.Parse(data)
	if err != nil || tree == nil {
		return nil
	}

	lines := newLineIndex(data)

	var findings []Finding
	findings = append(findings, l.detectNamed(file, data, tree, lines, set.Rules)...)
	findings = append(findings, l.detectValues(file, data, tree, lines, set)...)
	findings = append(findings, l.detectEnvFallback(file, data, tree, lines, set.Rules)...)
	findings = append(findings, l.detectCallArgSecret(file, data, tree, lines, set.Rules)...)
	findings = append(findings, l.detectLogicalDefault(file, data, tree, lines, set.Rules)...)
	return findings
}

// detectNamed applies name-driven detection: an assignment whose name signals a
// secret and whose value is a string literal (calls/identifiers were excluded by
// the query itself).
func (l *loadedLang) detectNamed(file string, data []byte, tree *ts.Tree, lines lineIndex, rules []Rule) []Finding {
	var findings []Finding

	for _, m := range l.pairQ.Execute(tree) {
		nameText, valueText, valueNode, line, ok := pairFromMatch(m, data, lines)
		if !ok {
			continue
		}

		// An interpolated literal (e.g. a Python f-string `f"sk_{var}"`) is not a
		// static secret; the AST lets us tell it apart from a plain string.
		if l.valueIsDynamic(valueNode) {
			continue
		}

		name := cleanSourceName(nameText)
		value := cleanSourceLiteral(valueText)
		path := fmt.Sprintf("line:%d", line)

		for _, rule := range rules {
			if !nameSignalsSecret(name, rule) {
				continue
			}
			if shouldSkipValue(value, rule) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" && !isLikelySecretValue(name, value, rule) {
				continue
			}
			if reason == "" {
				reason = "source assignment name indicates secret and value is a string literal"
			}

			findings = append(findings, newFinding(
				file,
				path,
				"source_name",
				"source_value",
				name,
				value,
				reason,
			))
		}
	}

	return findings
}

// detectValues applies value-driven detection: any string literal whose shape
// matches a gitleaks pattern, regardless of the surrounding name.
func (l *loadedLang) detectValues(file string, data []byte, tree *ts.Tree, lines lineIndex, set RuleSet) []Finding {
	var findings []Finding

	for _, m := range l.valueQ.Execute(tree) {
		for i := range m.Captures {
			cap := m.Captures[i]
			if cap.Name != "value" {
				continue
			}
			if l.valueIsDynamic(cap.Node) {
				continue
			}

			value := cleanSourceLiteral(cap.Text(data))
			path := fmt.Sprintf("line:%d", lines.lineAt(int(cap.Node.StartByte())))
			findings = append(findings, detectValuePatterns(file, path, "", value, set)...)
		}
	}

	return findings
}

// detectEnvFallback flags a hardcoded fallback secret passed to an environment
// or config lookup, e.g. os.getenv("DB_PASSWORD", "hunter2"). The fallback is a
// real secret in source even though it is the *second* argument of a call — the
// AST lets us reach it, where a call-skipping scanner cannot.
//
// It only fires the name-driven case (the env key / first argument signals a
// secret); a fallback whose *shape* matches a gitleaks pattern is already caught
// by detectValues, which scans every string literal including this one.
func (l *loadedLang) detectEnvFallback(file string, data []byte, tree *ts.Tree, lines lineIndex, rules []Rule) []Finding {
	if l.envQ == nil {
		return nil
	}

	var findings []Finding

	for _, m := range l.envQ.Execute(tree) {
		var fn, envName, value string
		var valueNode *ts.Node
		var line int
		for i := range m.Captures {
			switch m.Captures[i].Name {
			case "fn":
				fn = m.Captures[i].Text(data)
			case "envname":
				envName = m.Captures[i].Text(data)
			case "value":
				value = m.Captures[i].Text(data)
				valueNode = m.Captures[i].Node
				line = lines.lineAt(int(m.Captures[i].Node.StartByte()))
			}
		}

		if valueNode == nil || !envLookupRe.MatchString(fn) {
			continue
		}
		if l.valueIsDynamic(valueNode) {
			continue
		}

		name := cleanSourceName(envName)
		val := cleanSourceLiteral(value)
		path := fmt.Sprintf("line:%d", line)

		for _, rule := range rules {
			if !nameSignalsSecret(name, rule) {
				continue
			}
			if shouldSkipValue(val, rule) {
				continue
			}

			reason := classifySecretReason(val)
			if reason == "" && !isLikelySecretValue(name, val, rule) {
				continue
			}
			if reason == "" {
				reason = "env lookup key indicates secret and fallback value is a string literal"
			}

			findings = append(findings, newFinding(
				file,
				path,
				"env_default_name",
				"env_default_value",
				name,
				val,
				reason,
			))
		}
	}

	return findings
}

// detectCallArgSecret flags a secret passed as a string-literal argument to any
// call, when the assignment target signals a secret — e.g.
// password = vault.fetch("key", "s3cr3t!"). The right-hand side is a call (not a
// literal), so the name-driven pass skips it; reaching the argument requires the
// AST. The value is gated more strictly (looksLikeArgSecret) because call
// arguments are commonly benign prose (labels, prompts, format strings).
func (l *loadedLang) detectCallArgSecret(file string, data []byte, tree *ts.Tree, lines lineIndex, rules []Rule) []Finding {
	if l.callArgQ == nil {
		return nil
	}

	var findings []Finding

	for _, m := range l.callArgQ.Execute(tree) {
		var nameText, fn, valueText string
		var valueNode *ts.Node
		var line int
		for i := range m.Captures {
			switch m.Captures[i].Name {
			case "name":
				nameText = m.Captures[i].Text(data)
			case "fn":
				fn = m.Captures[i].Text(data)
			case "value":
				valueText = m.Captures[i].Text(data)
				valueNode = m.Captures[i].Node
				line = lines.lineAt(int(m.Captures[i].Node.StartByte()))
			}
		}

		if valueNode == nil || l.valueIsDynamic(valueNode) {
			continue
		}

		// Environment/config lookups are handled by the env-fallback pass; here
		// their argument is the key *name*, not a secret value, so skip them.
		if envLookupRe.MatchString(fn) || envRefRe.MatchString(fn) {
			continue
		}

		name := cleanSourceName(nameText)
		value := cleanSourceLiteral(valueText)
		path := fmt.Sprintf("line:%d", line)

		for _, rule := range rules {
			if !nameSignalsSecret(name, rule) {
				continue
			}
			if shouldSkipValue(value, rule) || !looksLikeArgSecret(name, value, rule) {
				continue
			}

			reason := classifySecretReason(value)
			if reason == "" {
				reason = "secret-named assignment passes a string literal into a call"
			}

			findings = append(findings, newFinding(
				file,
				path,
				"call_arg_name",
				"call_arg_value",
				name,
				value,
				reason,
			))
		}
	}

	return findings
}

// detectLogicalDefault flags a hardcoded default behind a logical-OR or
// null-coalescing read of the environment, e.g. process.env.KEY || "fallback"
// or GetEnvironmentVariable("K") ?? "fallback". The operator is read from the
// AST so that comparisons (process.env.MODE == "prod") are not mistaken for
// defaults, and the left operand must be an environment reference.
func (l *loadedLang) detectLogicalDefault(file string, data []byte, tree *ts.Tree, lines lineIndex, rules []Rule) []Finding {
	if l.logicalQ == nil {
		return nil
	}

	var findings []Finding

	for _, m := range l.logicalQ.Execute(tree) {
		var lookup, value string
		var valueNode, exprNode *ts.Node
		var line int
		for i := range m.Captures {
			switch m.Captures[i].Name {
			case "lookup":
				lookup = m.Captures[i].Text(data)
			case "value":
				value = m.Captures[i].Text(data)
				valueNode = m.Captures[i].Node
				line = lines.lineAt(int(m.Captures[i].Node.StartByte()))
			case "expr":
				exprNode = m.Captures[i].Node
			}
		}

		if valueNode == nil || exprNode == nil {
			continue
		}
		if !defaultOperators[l.operatorText(exprNode, data)] {
			continue
		}
		if !envRefRe.MatchString(lookup) || l.valueIsDynamic(valueNode) {
			continue
		}

		name := cleanSourceName(envNameFromLookup(lookup))
		val := cleanSourceLiteral(value)
		path := fmt.Sprintf("line:%d", line)

		for _, rule := range rules {
			if !nameSignalsSecret(name, rule) {
				continue
			}
			if shouldSkipValue(val, rule) || !looksLikeArgSecret(name, val, rule) {
				continue
			}

			reason := classifySecretReason(val)
			if reason == "" {
				reason = "env default value (logical fallback) is a hardcoded string literal"
			}

			findings = append(findings, newFinding(
				file,
				path,
				"env_default_name",
				"env_default_value",
				name,
				val,
				reason,
			))
		}
	}

	return findings
}

// operatorText returns the text of an expression node's operator field (e.g.
// "||", "??", "or"), or "" when there is none.
func (l *loadedLang) operatorText(expr *ts.Node, data []byte) string {
	op := expr.ChildByFieldName("operator", l.lang)
	if op == nil {
		return ""
	}
	return op.Text(data)
}

// pairFromMatch extracts the @name text, @value text, @value node, and 1-based
// line of @value from a query match. It reports ok=false when either capture is
// absent.
func pairFromMatch(m ts.QueryMatch, data []byte, lines lineIndex) (name, value string, valueNode *ts.Node, line int, ok bool) {
	var haveName, haveValue bool
	for i := range m.Captures {
		switch m.Captures[i].Name {
		case "name":
			name = m.Captures[i].Text(data)
			haveName = true
		case "value":
			value = m.Captures[i].Text(data)
			valueNode = m.Captures[i].Node
			line = lines.lineAt(int(m.Captures[i].Node.StartByte()))
			haveValue = true
		}
	}
	return name, value, valueNode, line, haveName && haveValue
}

// dynamicLiteralChildTypes are node types that, when present inside a string
// literal, mean the value is computed at runtime rather than fixed — an
// interpolation/substitution. Such values are not static secrets.
var dynamicLiteralChildTypes = map[string]bool{
	"interpolation":         true, // Python f-strings, others
	"template_substitution": true, // JS/TS template literals
	"string_interpolation":  true,
}

// valueIsDynamic reports whether a captured string-literal node contains an
// interpolation, i.e. part of its content is computed at runtime. This is the
// literal-vs-dynamic distinction that regex scanners cannot make.
func (l *loadedLang) valueIsDynamic(n *ts.Node) bool {
	if n == nil {
		return false
	}

	for i := 0; i < n.ChildCount(); i++ {
		child := n.Child(i)
		if child == nil {
			continue
		}
		if dynamicLiteralChildTypes[child.Type(l.lang)] {
			return true
		}
	}

	return false
}

// cleanSourceName normalizes a captured name node's text (an identifier, or a
// quoted dict/object key) into a bare key name.
func cleanSourceName(s string) string {
	return normalizeScalar(s)
}

// cleanSourceLiteral extracts the textual content of a source string literal,
// stripping language string prefixes (Python r/b/f/u, C# @/$) and the
// surrounding quote delimiters (single, double, triple, or backtick). Escape
// sequences inside the literal are left as-is, which is adequate for the
// shape/keyword heuristics applied downstream.
func cleanSourceLiteral(s string) string {
	s = strings.TrimSpace(s)

	for len(s) > 1 && isStringPrefix(s[0]) && isQuote(s[1]) {
		s = s[1:]
	}

	for _, q := range []string{`"""`, "'''"} {
		if len(s) >= 2*len(q) && strings.HasPrefix(s, q) && strings.HasSuffix(s, q) {
			return s[len(q) : len(s)-len(q)]
		}
	}

	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if isQuote(first) && first == last {
			return s[1 : len(s)-1]
		}
	}

	return s
}

func isStringPrefix(b byte) bool {
	switch b {
	case 'r', 'b', 'f', 'u', 'R', 'B', 'F', 'U', '@', '$':
		return true
	}
	return false
}

func isQuote(b byte) bool {
	return b == '"' || b == '\'' || b == '`'
}

// lineIndex maps byte offsets to 1-based line numbers via the sorted offsets of
// each line's first byte.
type lineIndex struct {
	starts []int
}

func newLineIndex(data []byte) lineIndex {
	starts := []int{0}
	for i, b := range data {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return lineIndex{starts: starts}
}

func (li lineIndex) lineAt(byteOffset int) int {
	lo, hi := 0, len(li.starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if li.starts[mid] <= byteOffset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}
