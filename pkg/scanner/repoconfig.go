package scanner

import (
	"fmt"
	"os"
	"path/filepath"
)

// RepoConfigNames are the file names looked for at a repository root (a directory
// containing a ".git" entry). The first one found provides a repo-local config
// that overrides the base config for files within that repository.
var RepoConfigNames = []string{".confessecrets.yaml", ".confessecrets.yml"}

// effectiveConfig pairs a parsed config with its compiled rules.
type effectiveConfig struct {
	cfg   Config
	rules []Rule
}

// ConfigResolver resolves the effective scanner config for a file path. When
// enabled, it honors repo-local config files (see RepoConfigNames) discovered at
// repository roots: a file is governed by the config of its nearest enclosing
// repository, falling back to the base config when that repo has none. A
// repository root acts as a boundary — a repo without its own config uses the
// base config rather than inheriting an outer repo's. Results are memoized per
// directory, so each repo root is stat'd and parsed at most once.
type ConfigResolver struct {
	base    effectiveConfig
	enabled bool
	root    string
	cache   map[string]effectiveConfig
}

// NewConfigResolver builds a resolver over base/baseRules. enabled toggles
// repo-local config discovery; root bounds the upward search so the resolver
// never climbs above the scanned tree.
func NewConfigResolver(base Config, baseRules []Rule, enabled bool, root string) *ConfigResolver {
	return &ConfigResolver{
		base:    effectiveConfig{cfg: base, rules: baseRules},
		enabled: enabled,
		root:    filepath.Clean(root),
		cache:   map[string]effectiveConfig{},
	}
}

// Resolve returns the config and compiled rules that should govern scanning path.
func (r *ConfigResolver) Resolve(path string) (Config, []Rule) {
	eff := r.forDir(filepath.Dir(path))
	return eff.cfg, eff.rules
}

func (r *ConfigResolver) forDir(dir string) effectiveConfig {
	if !r.enabled {
		return r.base
	}

	dir = filepath.Clean(dir)
	if eff, ok := r.cache[dir]; ok {
		return eff
	}

	eff := r.computeDir(dir)
	r.cache[dir] = eff
	return eff
}

func (r *ConfigResolver) computeDir(dir string) effectiveConfig {
	// A repository root is a boundary: its own config governs the subtree, and a
	// repo without a config uses the base rather than inheriting from above.
	if isRepoRoot(dir) {
		if eff, ok := r.loadRepoConfig(dir); ok {
			return eff
		}
		return r.base
	}

	parent := filepath.Dir(dir)
	if dir == r.root || parent == dir {
		return r.base
	}
	return r.forDir(parent)
}

// loadRepoConfig loads and compiles the first repo-local config present in dir.
// It returns ok=false when none exists; a config that fails to load or compile
// is reported and treated as absent so the scan continues with the base config.
func (r *ConfigResolver) loadRepoConfig(dir string) (effectiveConfig, bool) {
	for _, name := range RepoConfigNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}

		cfg, err := LoadConfig(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip repo config %s: %v\n", path, err)
			return effectiveConfig{}, false
		}

		rules, err := CompileRules(cfg.Rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip repo config %s: %v\n", path, err)
			return effectiveConfig{}, false
		}

		return effectiveConfig{cfg: cfg, rules: rules}, true
	}

	return effectiveConfig{}, false
}

// isRepoRoot reports whether dir is a git repository root, i.e. it contains a
// ".git" entry. The entry may be a directory (normal clone) or a file (worktrees
// and submodules use a ".git" file pointing elsewhere), so its type is ignored.
func isRepoRoot(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}
