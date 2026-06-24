package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// repoLocalConfig is a minimal valid config whose single rule flags any
// populated value, so we can tell which config governed a given file.
const repoLocalConfig = `
files:
  allow:
    - "**/*.yaml"
rules:
  - name_paths: [name]
    value_paths: [value]
    name_regex: '(?i)secret'
    min_value_len: 1
`

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func markRepoRoot(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestIsRepoRoot(t *testing.T) {
	root := t.TempDir()

	if isRepoRoot(root) {
		t.Errorf("isRepoRoot(%q) = true before .git exists", root)
	}

	// A .git file (worktree/submodule style) counts, not just a directory.
	writeFile(t, filepath.Join(root, ".git"), "gitdir: /elsewhere\n")
	if !isRepoRoot(root) {
		t.Errorf("isRepoRoot(%q) = false with .git file present", root)
	}
}

func baseConfigAndRules(t *testing.T) (Config, []Rule) {
	t.Helper()
	base := Config{
		Files: FilePolicy{Allow: []string{"**/*.yaml"}},
		Rules: []RuleConfig{{
			NamePaths:  []string{"name"},
			ValuePaths: []string{"value"},
			NameRegex:  "(?i)never-matches-anything-xyzzy",
		}},
	}
	rules, err := CompileRules(base.Rules)
	if err != nil {
		t.Fatalf("CompileRules: %v", err)
	}
	return base, rules
}

func TestConfigResolverRespectsRepoConfig(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repoA")
	markRepoRoot(t, repo)
	writeFile(t, filepath.Join(repo, RepoConfigNames[0]), repoLocalConfig)

	base, baseRules := baseConfigAndRules(t)
	r := NewConfigResolver(base, baseRules, true, root)

	// A file inside repoA must resolve to repoA's local config (its rule matches
	// "secret", unlike the base rule).
	_, rules := r.Resolve(filepath.Join(repo, "app.yaml"))
	if len(rules) != 1 || !rules[0].NameRegex.MatchString("secret") {
		t.Fatalf("file inside repo did not get repo-local rules: %+v", rules)
	}

	// A file outside any repo uses the base config.
	_, rules = r.Resolve(filepath.Join(root, "top.yaml"))
	if len(rules) != 1 || rules[0].NameRegex.MatchString("secret") {
		t.Errorf("file outside repo did not get base rules: %+v", rules)
	}
}

func TestConfigResolverDisabledIgnoresRepoConfig(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repoA")
	markRepoRoot(t, repo)
	writeFile(t, filepath.Join(repo, RepoConfigNames[0]), repoLocalConfig)

	base, baseRules := baseConfigAndRules(t)
	r := NewConfigResolver(base, baseRules, false, root)

	_, rules := r.Resolve(filepath.Join(repo, "app.yaml"))
	if rules[0].NameRegex.MatchString("secret") {
		t.Errorf("repo config was honored despite being disabled: %+v", rules)
	}
}

func TestConfigResolverRepoWithoutConfigUsesBase(t *testing.T) {
	root := t.TempDir()

	// Outer repo has a local config; inner repo (nested) has none and must fall
	// back to the base config rather than inheriting the outer repo's.
	outer := filepath.Join(root, "outer")
	markRepoRoot(t, outer)
	writeFile(t, filepath.Join(outer, RepoConfigNames[0]), repoLocalConfig)

	inner := filepath.Join(outer, "vendor", "inner")
	markRepoRoot(t, inner)

	base, baseRules := baseConfigAndRules(t)
	r := NewConfigResolver(base, baseRules, true, root)

	_, rules := r.Resolve(filepath.Join(inner, "app.yaml"))
	if rules[0].NameRegex.MatchString("secret") {
		t.Errorf("nested repo without config inherited outer repo config: %+v", rules)
	}
}
