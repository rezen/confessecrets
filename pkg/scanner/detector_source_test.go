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
			code: `password = vault.fetch("key", "SECER$%$%$hERE")
api = os.getenv("API_KEY") or "pyorfallbacksecret"
prompt_pw = getpass("Enter Password: ")`,
			wantFlag:   []string{"SECER$%$%$hERE", "pyorfallbacksecret"},
			wantAbsent: []string{"key", "Enter Password: "},
		},
		{
			name: "js-logical-default-and-comparison",
			ext:  ".js",
			code: `const k = process.env.API_KEY || "jsorfallbacksecret";
const password = vault.fetch("key", "JSARG$secret123");
const mode = process.env.API_KEY == "shouldnotflagcompare";`,
			wantFlag:   []string{"jsorfallbacksecret", "JSARG$secret123"},
			wantAbsent: []string{"shouldnotflagcompare", "key"},
		},
		{
			name: "csharp-null-coalescing",
			ext:  ".cs",
			code: `class C { void M() {
    string k = System.Environment.GetEnvironmentVariable("API_KEY") ?? "csorfallbacksecret";
} }`,
			wantFlag:   []string{"csorfallbacksecret"},
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
			code: `password = "hunter2supersecret"
api_token = os.environ.get("SHOULD_NOT_FLAG_PY")
creds = {"secret": "dictsecretvalue123"}
secret_key = f"hunter2dynamic{tail}"
db_default = os.getenv("DB_PASSWORD", "plainfallbackpw123")
port = os.getenv("PORT", "8080")
aws_key = "` + awsToken + `"
`,
			wantFlag:   []string{"hunter2supersecret", "dictsecretvalue123", "plainfallbackpw123", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_PY", "hunter2dynamic{tail}", "8080"},
		},
		{
			name: "javascript",
			ext:  ".js",
			code: `const password = "hunter2supersecret";
const apiToken = getEnv("SHOULD_NOT_FLAG_JS");
const obj = { secret: "objsecretvalue123" };
const dbpw = getEnv("DB_PASSWORD", "jsfallbacksecret123");
const awsKey = "` + awsToken + `";
`,
			wantFlag:   []string{"hunter2supersecret", "objsecretvalue123", "jsfallbacksecret123", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_JS"},
		},
		{
			name: "typescript",
			ext:  ".ts",
			code: `const password: string = "hunter2supersecret";
const apiToken: string = getEnv("SHOULD_NOT_FLAG_TS");
const awsKey = "` + awsToken + `";
`,
			wantFlag:   []string{"hunter2supersecret", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_TS"},
		},
		{
			name: "go",
			ext:  ".go",
			code: `package main

import "os"

type Config struct{ APIKey string }

func main() {
	password := "hunter2supersecret"
	apiToken := os.Getenv("SHOULD_NOT_FLAG_GO")
	awsKey := "` + awsToken + `"
	cfg := Config{APIKey: "structsecretvalue123"}
	_, _, _, _ = password, apiToken, awsKey, cfg
}
`,
			wantFlag:   []string{"hunter2supersecret", awsToken, "structsecretvalue123"},
			wantAbsent: []string{"SHOULD_NOT_FLAG_GO"},
		},
		{
			name: "java",
			ext:  ".java",
			code: `class C {
  void m() {
    String password = "hunter2supersecret";
    String apiToken = System.getenv("SHOULD_NOT_FLAG_JAVA");
    String dbpw = props.getOrDefault("DB_PASSWORD", "javafallbacksecret123");
    String awsKey = "` + awsToken + `";
  }
}
`,
			wantFlag:   []string{"hunter2supersecret", "javafallbacksecret123", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_JAVA"},
		},
		{
			name: "c_sharp",
			ext:  ".cs",
			code: `class C {
  void M() {
    string password = "hunter2supersecret";
    string apiToken = System.Environment.GetEnvironmentVariable("SHOULD_NOT_FLAG_CS");
    string dbpw = config.GetValue("DB_PASSWORD", "csfallbacksecret123");
    string awsKey = "` + awsToken + `";
  }
}
`,
			wantFlag:   []string{"hunter2supersecret", "csfallbacksecret123", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_CS"},
		},
		{
			name: "ruby",
			ext:  ".rb",
			code: `password = "hunter2supersecret"
api_token = ENV["SHOULD_NOT_FLAG_RB"]
creds = {"secret" => "dictsecretvalue123"}
opts = {secret_key: "symsecretvalue123"}
db_default = ENV["DB_PASSWORD"] || "rbfallbacksecret123"
secret_key = "hunter2dynamic#{tail}"
aws_key = "` + awsToken + `"
`,
			wantFlag:   []string{"hunter2supersecret", "dictsecretvalue123", "symsecretvalue123", "rbfallbacksecret123", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_RB", "hunter2dynamic#{tail}"},
		},
		{
			name: "php",
			ext:  ".php",
			code: `<?php
$password = "hunter2supersecret";
$apiToken = getenv("SHOULD_NOT_FLAG_PHP");
$creds = ["secret" => "arraysecretvalue123"];
$dbpw = $_ENV["DB_PASSWORD"] ?? "phpfallbacksecret123";
$secretKey = "hunter2dynamic$tail";
$awsKey = "` + awsToken + `";
`,
			wantFlag:   []string{"hunter2supersecret", "arraysecretvalue123", "phpfallbacksecret123", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_PHP", "hunter2dynamic$tail"},
		},
		{
			name: "kotlin",
			ext:  ".kt",
			code: `val password = "hunter2supersecret"
val apiToken = System.getenv("SHOULD_NOT_FLAG_KT")
val dbpw = System.getenv("DB_PASSWORD") ?: "ktfallbacksecret123"
val secretKey = "hunter2dynamic$tail"
val awsKey = "` + awsToken + `"
`,
			wantFlag:   []string{"hunter2supersecret", "ktfallbacksecret123", awsToken},
			wantAbsent: []string{"SHOULD_NOT_FLAG_KT", "hunter2dynamic$tail"},
		},
		{
			name: "rust",
			ext:  ".rs",
			code: `fn main() {
    let password = "hunter2supersecret";
    let api_token = std::env::var("SHOULD_NOT_FLAG_RS").unwrap();
    const SECRET_KEY: &str = "constsecretvalue123";
    let aws_key = "` + awsToken + `";
    let _ = (password, api_token, aws_key);
}
`,
			wantFlag:   []string{"hunter2supersecret", "constsecretvalue123", awsToken},
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

func debugFindings(findings []Finding) string {
	var b []string
	for _, f := range findings {
		b = append(b, f.Name+"="+f.RawValue+" ("+f.Reason+")")
	}
	return "[" + strings.Join(b, ", ") + "]"
}
