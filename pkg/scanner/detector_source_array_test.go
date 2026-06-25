package scanner

import "testing"

// TestSourceArrayLiterals verifies name-driven detection reaches string literals
// nested inside list/array/collection literals assigned to a secret-named target,
// e.g. passwords = ["s3cr3t...", "an0th3r..."]. Each element must be flagged.
func TestSourceArrayLiterals(t *testing.T) {
	rules := testRules(t)

	cases := []struct {
		name     string
		ext      string
		code     string
		wantFlag []string
	}{
		{
			name: "python",
			ext:  ".py",
			code: `passwords = ["pyArr1secretVal", "pyArr2secretVal"]
tokens = ("pyTup1secretVal", "pyTup2secretVal")
creds = {"secret": ["pyDict1secretVal"]}`,
			wantFlag: []string{"pyArr1secretVal", "pyArr2secretVal", "pyTup1secretVal", "pyTup2secretVal", "pyDict1secretVal"},
		},
		{
			name: "javascript",
			ext:  ".js",
			code: `const passwords = ["jsArr1secretVal", "jsArr2secretVal"];
obj.apiKeys = ["jsMember1secretVal"];
const cfg = { secret: ["jsObj1secretVal"] };`,
			wantFlag: []string{"jsArr1secretVal", "jsArr2secretVal", "jsMember1secretVal", "jsObj1secretVal"},
		},
		{
			name:     "typescript",
			ext:      ".ts",
			code:     `const passwords: string[] = ["tsArr1secretVal", "tsArr2secretVal"];`,
			wantFlag: []string{"tsArr1secretVal", "tsArr2secretVal"},
		},
		{
			name: "go",
			ext:  ".go",
			code: `package main
func main() {
	passwords := []string{"goArr1secretVal", "goArr2secretVal"}
	var apiKeys = []string{"goVar1secretVal"}
	_ = passwords; _ = apiKeys
}`,
			wantFlag: []string{"goArr1secretVal", "goArr2secretVal", "goVar1secretVal"},
		},
		{
			name: "java",
			ext:  ".java",
			code: `class C { void m() {
	String[] passwords = {"javaArr1secretVal", "javaArr2secretVal"};
	String[] apiKeys = new String[]{"javaNew1secretVal"};
} }`,
			wantFlag: []string{"javaArr1secretVal", "javaArr2secretVal", "javaNew1secretVal"},
		},
		{
			name: "c_sharp",
			ext:  ".cs",
			code: `class C { void M() {
	string[] passwords = {"csArr1secretVal", "csArr2secretVal"};
	var apiKeys = new[]{"csImplicit1secretVal"};
	string[] secretKeys = new string[]{"csNew1secretVal"};
} }`,
			wantFlag: []string{"csArr1secretVal", "csArr2secretVal", "csImplicit1secretVal", "csNew1secretVal"},
		},
		{
			name: "ruby",
			ext:  ".rb",
			code: `passwords = ["rbArr1secretVal", "rbArr2secretVal"]
@api_keys = ["rbIvar1secretVal"]`,
			wantFlag: []string{"rbArr1secretVal", "rbArr2secretVal", "rbIvar1secretVal"},
		},
		{
			name:     "ruby-constant",
			ext:      ".rb",
			code:     `SECRET_TOKENS = ["rbConst1secretVal", "rbConst2secretVal"]`,
			wantFlag: []string{"rbConst1secretVal", "rbConst2secretVal"},
		},
		{
			name: "php",
			ext:  ".php",
			code: `<?php
$passwords = ["phpArr1secretVal", "phpArr2secretVal"];
$apiKeys = array("phpArrFn1secretVal");`,
			wantFlag: []string{"phpArr1secretVal", "phpArr2secretVal", "phpArrFn1secretVal"},
		},
		{
			name: "kotlin",
			ext:  ".kt",
			code: `val passwords = listOf("ktList1secretVal", "ktList2secretVal")
val apiKeys = arrayOf("ktArr1secretVal")`,
			wantFlag: []string{"ktList1secretVal", "ktList2secretVal", "ktArr1secretVal"},
		},
		{
			name: "rust",
			ext:  ".rs",
			code: `fn main() {
	let passwords = ["rsArr1secretVal", "rsArr2secretVal"];
	let api_keys = vec!["rsVec1secretVal"];
	let _ = (passwords, api_keys);
}`,
			wantFlag: []string{"rsArr1secretVal", "rsArr2secretVal", "rsVec1secretVal"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := sourceLangForExt(tc.ext)
			if spec == nil || defaultSourceEngine.langFor(spec) == nil {
				t.Fatalf("grammar/queries for %s failed to load", tc.ext)
			}

			findings := SourceDetector{}.Detect("sample"+tc.ext, []byte(tc.code), RuleSet{Rules: rules})
			got := rawValueSet(findings)

			for _, want := range tc.wantFlag {
				if !got[want] {
					t.Errorf("expected %q to be flagged, but it was not.\nfindings: %s", want, debugFindings(findings))
				}
			}
		})
	}
}
