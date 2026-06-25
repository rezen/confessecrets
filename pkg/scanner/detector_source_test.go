package scanner

import (
	"strings"
	"testing"
)

// rawValueSet returns the set of raw (unredacted) values across findings.
func rawValueSet(findings []Finding) map[string]bool {
	out := make(map[string]bool, len(findings))
	for _, f := range findings {
		out[f.RawValue] = true
	}
	return out
}

func TestIsSourceFile(t *testing.T) {
	source := []string{"a.py", "a.pyi", "b.js", "b.jsx", "c.ts", "c.tsx", "d.go", "e.java", "f.cs", "g.rb", "h.php", "i.kt", "i.kts", "j.rs", "DIR/UP.PY"}
	notSource := []string{"config.json", "values.yaml", "app.xml", ".env", "x.properties", "y.ini", "README.md", "noext"}

	for _, p := range source {
		if !IsSourceFile(p) {
			t.Errorf("IsSourceFile(%q) = false, want true", p)
		}
	}
	for _, p := range notSource {
		if IsSourceFile(p) {
			t.Errorf("IsSourceFile(%q) = true, want false", p)
		}
	}
}

// TestSourceArgsAndDefaults covers secrets that hide behind a call: a secret
// passed as a call argument (password = method("key", "secret")) and a hardcoded
// default behind a logical-OR / null-coalescing env read (X || "secret"). It also
// pins the false-positive guards: a comparison (== , not a default) and a prose
// prompt argument (contains whitespace) must not be flagged.
func TestSourceArgsAndDefaults(t *testing.T) {
	rules := testRules(t)

	cases := []struct {
		name       string
		ext        string
		code       string
		wantFlag   []string
		wantAbsent []string
	}{
		{
			name: "python-callarg-and-or-default",
			ext:  ".py",
			code: `password = vault.fetch("key", "K7q$%$%$Vp9Zb")
api = os.getenv("API_KEY") or "GvbT3skKp1sVtt7St"
prompt_pw = getpass("Enter Password: ")`,
			wantFlag:   []string{"K7q$%$%$Vp9Zb", "GvbT3skKp1sVtt7St"},
			wantAbsent: []string{"key", "Enter Password: "},
		},
		{
			name: "js-logical-default-and-comparison",
			ext:  ".js",
			code: `const k = process.env.API_KEY || "GvvS3rrGt6mMcc6Dh";
const password = vault.fetch("key", "JSARG$secret123");
const mode = process.env.API_KEY == "shouldnotflagcompare";`,
			wantFlag:   []string{"GvvS3rrGt6mMcc6Dh", "JSARG$secret123"},
			wantAbsent: []string{"shouldnotflagcompare", "key"},
		},
		{
			name: "csharp-null-coalescing",
			ext:  ".cs",
			code: `class C { void M() {
    string k = System.Environment.GetEnvironmentVariable("API_KEY") ?? "FvbV3dkRg4vRts2Ss";
} }`,
			wantFlag:   []string{"FvbV3dkRg4vRts2Ss"},
			wantAbsent: []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := sourceLangForExt(tc.ext)
			if spec == nil || defaultSourceEngine.langFor(spec) == nil {
				t.Fatalf("source language for %s unavailable", tc.ext)
			}

			findings := SourceDetector{}.Detect("sample"+tc.ext, []byte(tc.code), RuleSet{Rules: rules})
			got := rawValueSet(findings)

			for _, want := range tc.wantFlag {
				if !got[want] {
					t.Errorf("expected %q to be flagged, but it was not.\nfindings: %s", want, debugFindings(findings))
				}
			}
			for _, absent := range tc.wantAbsent {
				if got[absent] {
					t.Errorf("value %q should NOT be flagged, but it was.\nfindings: %s", absent, debugFindings(findings))
				}
			}
		})
	}
}

// TestSourceDetector exercises the tree-sitter source scanner across every
// supported language. The defining behavior under test: a secret-named
// assignment to a *string literal* is flagged, but the same name assigned from a
// runtime lookup (os.environ.get / getenv / process.env) is not — the value node
// is a call, not a literal. It also checks value-shape (gitleaks) detection on
// bare literals.
//
// Grammars are embedded in the binary (pure-Go runtime), so this runs anywhere
// with no setup, downloads, or native libraries.
func TestSourceDetector(t *testing.T) {
	rules := testRules(t)

	const awsToken = "AKIAIOSFODNN7EXAMPLE" // matches the gitleaks aws-access-token shape

	cases := []struct {
		name       string
		ext        string
		code       string
		wantFlag   []string // raw values that MUST be reported
		wantAbsent []string // values that must NOT be reported (literal args of lookups)
	}{
		{
			name: "python",
			ext:  ".py",
			code: `password = "DnsG3tmHg6hTgv3Kd"
api_token = os.environ.get("SHOULD_NOT_FLAG_PY")
creds = {"secret": "DjnR3mpFb3kSnc5Fd"}
secret_key = f"hunter2dynamic{tail}"
db_default = os.getenv("DB_PASSWORD", "NntJ4sqRh1qGmk2Pg")
port = os.getenv("PORT", "8080")
aws_key = "` + awsToken + `"
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "DjnR3mpFb3kSnc5Fd", "NntJ4sqRh1qGmk2Pg", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_PY", "hunter2dynamic{tail}", "8080"},
		},
		{
			name: "javascript",
			ext:  ".js",
			code: `const password = "DnsG3tmHg6hTgv3Kd";
const apiToken = getEnv("SHOULD_NOT_FLAG_JS");
const obj = { secret: "GtvD2dsHj2pBfq3Sj" };
const dbpw = getEnv("DB_PASSWORD", "GkqC0bbBj4fFnq5Pj");
const awsKey = "` + awsToken + `";
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "GtvD2dsHj2pBfq3Sj", "GkqC0bbBj4fFnq5Pj", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_JS"},
		},
		{
			name: "typescript",
			ext:  ".ts",
			code: `const password: string = "DnsG3tmHg6hTgv3Kd";
const apiToken: string = getEnv("SHOULD_NOT_FLAG_TS");
const awsKey = "` + awsToken + `";
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_TS"},
		},
		{
			name: "go",
			ext:  ".go",
			code: `package main

import "os"

type Config struct{ APIKey string }

func main() {
	password := "DnsG3tmHg6hTgv3Kd"
	apiToken := os.Getenv("SHOULD_NOT_FLAG_GO")
	awsKey := "` + awsToken + `"
	cfg := Config{APIKey: "FbdH3hsPn3kJmh4Pt"}
	_, _, _, _ = password, apiToken, awsKey, cfg
}
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", awsToken, "FbdH3hsPn3kJmh4Pt"},
			wantAbsent: []string{"SHOULD_NOT_FLAG_GO"},
		},
		{
			name: "java",
			ext:  ".java",
			code: `class C {
  void m() {
    String password = "DnsG3tmHg6hTgv3Kd";
    String apiToken = System.getenv("SHOULD_NOT_FLAG_JAVA");
    String dbpw = props.getOrDefault("DB_PASSWORD", "CfmC4dmKt4gMth2Rq");
    String awsKey = "` + awsToken + `";
  }
}
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "CfmC4dmKt4gMth2Rq", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_JAVA"},
		},
		{
			name: "c_sharp",
			ext:  ".cs",
			code: `class C {
  void M() {
    string password = "DnsG3tmHg6hTgv3Kd";
    string apiToken = System.Environment.GetEnvironmentVariable("SHOULD_NOT_FLAG_CS");
    string dbpw = config.GetValue("DB_PASSWORD", "MrpH5dtNs5jQvg4Mj");
    string awsKey = "` + awsToken + `";
  }
}
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "MrpH5dtNs5jQvg4Mj", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_CS"},
		},
		{
			name: "ruby",
			ext:  ".rb",
			code: `password = "DnsG3tmHg6hTgv3Kd"
api_token = ENV["SHOULD_NOT_FLAG_RB"]
creds = {"secret" => "DjnR3mpFb3kSnc5Fd"}
opts = {secret_key: "SfdT0hdBt5bKss4Tj"}
db_default = ENV["DB_PASSWORD"] || "KgnB4sjKq9jKvb0Rg"
secret_key = "hunter2dynamic#{tail}"
aws_key = "` + awsToken + `"
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "DjnR3mpFb3kSnc5Fd", "SfdT0hdBt5bKss4Tj", "KgnB4sjKq9jKvb0Rg", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_RB", "hunter2dynamic#{tail}"},
		},
		{
			name: "php",
			ext:  ".php",
			code: `<?php
$password = "DnsG3tmHg6hTgv3Kd";
$apiToken = getenv("SHOULD_NOT_FLAG_PHP");
$creds = ["secret" => "HkdJ8vsTg5fVgb3Gf"];
$dbpw = $_ENV["DB_PASSWORD"] ?? "NvgF2knTr8vQkk4Vv";
$secretKey = "hunter2dynamic$tail";
$awsKey = "` + awsToken + `";
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "HkdJ8vsTg5fVgb3Gf", "NvgF2knTr8vQkk4Vv", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_PHP", "hunter2dynamic$tail"},
		},
		{
			name: "kotlin",
			ext:  ".kt",
			code: `val password = "DnsG3tmHg6hTgv3Kd"
val apiToken = System.getenv("SHOULD_NOT_FLAG_KT")
val dbpw = System.getenv("DB_PASSWORD") ?: "CjfG2cfFk1qMks3Hf"
val secretKey = "hunter2dynamic$tail"
val awsKey = "` + awsToken + `"
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "CjfG2cfFk1qMks3Hf", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_KT", "hunter2dynamic$tail"},
		},
		{
			name: "rust",
			ext:  ".rs",
			code: `fn main() {
    let password = "DnsG3tmHg6hTgv3Kd";
    let api_token = std::env::var("SHOULD_NOT_FLAG_RS").unwrap();
    const SECRET_KEY: &str = "NcrG0dsTb7nGnc8Cm";
    let aws_key = "` + awsToken + `";
    let _ = (password, api_token, aws_key);
}
`,
			wantFlag:   []string{"DnsG3tmHg6hTgv3Kd", "NcrG0dsTb7nGnc8Cm", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_RS"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := sourceLangForExt(tc.ext)
			if spec == nil {
				t.Fatalf("no source language registered for %s", tc.ext)
			}
			if defaultSourceEngine.langFor(spec) == nil {
				t.Fatalf("grammar/queries for %s failed to load", spec.name)
			}

			findings := SourceDetector{}.Detect("sample"+tc.ext, []byte(tc.code), RuleSet{Rules: rules})
			got := rawValueSet(findings)

			for _, want := range tc.wantFlag {
				if !got[want] {
					t.Errorf("expected %q to be flagged, but it was not.\nfindings: %s", want, debugFindings(findings))
				}
			}
			for _, absent := range tc.wantAbsent {
				if got[absent] {
					t.Errorf("value %q should NOT be flagged (it is a runtime lookup), but it was", absent)
				}
			}
		})
	}
}

// TestSourceValuePatternRetainsName checks that a value-shape match found in a
// named assignment keeps the variable name rather than reporting an empty one.
func TestSourceValuePatternRetainsName(t *testing.T) {
	spec := sourceLangForExt(".py")
	if spec == nil || defaultSourceEngine.langFor(spec) == nil {
		t.Skip("python grammar unavailable")
	}

	code := "azure_url = \"https://myapp.azurewebsites.net/api\"\n"
	findings := SourceDetector{}.Detect("sample.py", []byte(code), RuleSet{Rules: testRules(t)})

	var info *Finding
	for i := range findings {
		if findings[i].Reason == "info:azure-app-service" {
			info = &findings[i]
		}
	}
	if info == nil {
		t.Fatalf("expected info:azure-app-service finding, got %s", debugFindings(findings))
	}
	if info.Name != "azure_url" {
		t.Errorf("name = %q, want azure_url (retained from the assignment)", info.Name)
	}
	if info.Level != levelInfo {
		t.Errorf("level = %q, want %q", info.Level, levelInfo)
	}
	if info.Line != 1 {
		t.Errorf("line = %d, want 1", info.Line)
	}
}

// TestSourceFindingsAreSourceOrdered checks that the detector returns findings in
// source-line order even though a value-shape finding (the URL on line 2) is
// produced by a later pass than the name-driven FUNCTION_KEY on line 3. Source
// order is what lets correlation see the URL as a prior finding.
func TestSourceFindingsAreSourceOrdered(t *testing.T) {
	spec := sourceLangForExt(".py")
	if spec == nil || defaultSourceEngine.langFor(spec) == nil {
		t.Skip("python grammar unavailable")
	}

	code := "BASE_URL = \"https://func-x.azurewebsites.net/api\"\n" +
		"FUNCTION_KEY = \"6v-bssdfsdfdfbbbbb-rR2XzcbVAzFuV2exJw==\"\n"
	findings := SourceDetector{}.Detect("function_url.py", []byte(code), RuleSet{Rules: testRules(t)})

	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %s", debugFindings(findings))
	}
	if findings[0].Name != "BASE_URL" || findings[1].Name != "FUNCTION_KEY" {
		t.Fatalf("findings not in source order: %s", debugFindings(findings))
	}
}

// TestFunctionURLCorrelatesUppercaseNames is the end-to-end check for the
// reported case: an upper-case BASE_URL endpoint on an earlier line must fold
// into the FUNCTION_KEY secret via the built-in function-url correlation.
func TestFunctionURLCorrelatesUppercaseNames(t *testing.T) {
	spec := sourceLangForExt(".py")
	if spec == nil || defaultSourceEngine.langFor(spec) == nil {
		t.Skip("python grammar unavailable")
	}

	set := RuleSet{Rules: testRules(t), Correlations: mustCorrelations(t, nil)}
	code := "BASE_URL = \"https://func-x.azurewebsites.net/api\"\n" +
		"FUNCTION_KEY = \"6v-bssdfsdfdfbbbbb-rR2XzcbVAzFuV2exJw==\"\n"
	findings := correlateFindings(
		SourceDetector{}.Detect("function_url.py", []byte(code), set),
		set.Correlations,
	)

	if len(findings) != 1 {
		t.Fatalf("want 1 root finding (URL folded in), got %s", debugFindings(findings))
	}
	primary := findings[0]
	if primary.Name != "FUNCTION_KEY" {
		t.Fatalf("primary = %q, want FUNCTION_KEY", primary.Name)
	}
	if !hasTag(primary.Tags, "function-url") {
		t.Errorf("primary missing function-url tag: %v", primary.Tags)
	}
	if len(primary.Correlated) != 1 || primary.Correlated[0].Name != "BASE_URL" {
		t.Fatalf("want BASE_URL embedded as secondary, got %+v", primary.Correlated)
	}
}

func debugFindings(findings []Finding) string {
	var b []string
	for _, f := range findings {
		b = append(b, f.Name+"="+f.RawValue+" ("+f.Reason+")")
	}
	return "[" + strings.Join(b, ", ") + "]"
}
