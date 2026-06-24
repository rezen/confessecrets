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
    name_regexes:
      - '(?i)secret'
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

func baseConfigAndRules(t *testing.T) (Config, RuleSet) {
	t.Helper()
	base := Config{
		Files: FilePolicy{Allow: []string{"**/*.yaml"}},
		Rules: []RuleConfig{{
			NamePaths:   []string{"name"},
			ValuePaths:  []string{"value"},
			NameRegexes: []NameRegexEntry{{Regex: "(?i)never-matches-anything-xyzzy"}},
		}},
	}
	set, err := CompileConfig(base)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return base, set
}

func TestConfigResolverRespectsRepoConfig(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repoA")
	markRepoRoot(t, repo)
	writeFile(t, filepath.Join(repo, RepoConfigNames[0]), repoLocalConfig)

	base, baseSet := baseConfigAndRules(t)
	r := NewConfigResolver(base, baseSet, true, root)

	// A file inside repoA must resolve to repoA's local config (its rule matches
	// "secret", unlike the base rule).
	_, set := r.Resolve(filepath.Join(repo, "app.yaml"))
	if len(set.Rules) != 1 || !matchesAnyNameRegex("secret", set.Rules[0]) {
		t.Fatalf("file inside repo did not get repo-local rules: %+v", set.Rules)
	}

	// A file outside any repo uses the base config.
	_, set = r.Resolve(filepath.Join(root, "top.yaml"))
	if len(set.Rules) != 1 || matchesAnyNameRegex("secret", set.Rules[0]) {
		t.Errorf("file outside repo did not get base rules: %+v", set.Rules)
	}
}

func TestConfigResolverDisabledIgnoresRepoConfig(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repoA")
	markRepoRoot(t, repo)
	writeFile(t, filepath.Join(repo, RepoConfigNames[0]), repoLocalConfig)

	base, baseSet := baseConfigAndRules(t)
	r := NewConfigResolver(base, baseSet, false, root)

	_, set := r.Resolve(filepath.Join(repo, "app.yaml"))
	if matchesAnyNameRegex("secret", set.Rules[0]) {
		t.Errorf("repo config was honored despite being disabled: %+v", set.Rules)
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

	base, baseSet := baseConfigAndRules(t)
	r := NewConfigResolver(base, baseSet, true, root)

	_, set := r.Resolve(filepath.Join(inner, "app.yaml"))
	if matchesAnyNameRegex("secret", set.Rules[0]) {
		t.Errorf("nested repo without config inherited outer repo config: %+v", set.Rules)
	}
}
