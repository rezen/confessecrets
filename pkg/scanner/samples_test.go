package scanner_test

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezen/confessecrets/pkg/scanner"
)

// updateSamples, when set via -update, rewrites every samples/*.verify with the
// scanner's current output instead of asserting against it. Use it to seed a new
// sample's .verify or to refresh expectations after an intended behavior change;
// review the resulting diff before committing.
var updateSamples = flag.Bool("update", false, "rewrite samples/*.verify golden files from current scanner output")

// TestSamples is a golden-file test driven by the files in the repo's samples/
// directory. Every sample (e.g. samples/function_url.py) has a sibling .verify
// file (samples/function_url.verify) holding the exact NDJSON the scanner should
// emit for it: one JSON finding per line, in order. The test scans each sample
// with the repo's config.yaml and asserts the output matches its .verify byte
// for byte. To add a case, drop in a sample plus its .verify; to regenerate the
// expected output after an intended change, run with -update.
//
// Paths are repo-root relative so the "file" field in the output (which echoes
// the scanned path) matches what the CLI produces, so the test chdirs to the
// repo root for its duration.
func TestSamples(t *testing.T) {
	root := repoRoot(t)
	chdir(t, root)

	cfg, err := scanner.LoadConfig("config.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	set, err := scanner.CompileConfig(cfg)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}

	verifies, err := filepath.Glob(filepath.Join("samples", "*.verify"))
	if err != nil {
		t.Fatalf("glob samples: %v", err)
	}

	if len(verifies) == 0 {
		t.Fatal("no samples/*.verify files found")
	}

	for _, verifyPath := range verifies {
		target := sampleTarget(verifyPath)

		t.Run(filepath.Base(target), func(t *testing.T) {
			if _, err := os.Stat(target); err != nil {
				t.Fatalf("verify file %s has no matching sample %s: %v", verifyPath, target, err)
			}

			findings, err := scanner.ScanFile(target, set, scanner.ScanOptions{})
			if err != nil {
				t.Fatalf("scan %s: %v", target, err)
			}

			got := renderNDJSON(t, findings)

			if *updateSamples {
				if err := os.WriteFile(verifyPath, []byte(got), 0o644); err != nil {
					t.Fatalf("update %s: %v", verifyPath, err)
				}
				return
			}

			wantBytes, err := os.ReadFile(verifyPath)
			if err != nil {
				t.Fatalf("read %s: %v", verifyPath, err)
			}

			if got != string(wantBytes) {
				t.Errorf("scan of %s does not match %s\n--- got ---\n%s\n--- want ---\n%s",
					target, verifyPath, got, wantBytes)
			}
		})
	}
}

// sampleTarget maps a .verify path to the sample file it describes by stripping
// the .verify extension (samples/x.py.verify is not used; the convention is
// samples/x.<ext> paired with samples/x.verify, so a sample whose own name has
// no extension would collide — none do).
func sampleTarget(verifyPath string) string {
	base := strings.TrimSuffix(verifyPath, ".verify")
	// The sample keeps its real extension; the verify file replaces it. Recover
	// the sample by globbing for the stem with any extension.
	matches, _ := filepath.Glob(base + ".*")
	for _, m := range matches {
		if !strings.HasSuffix(m, ".verify") {
			return m
		}
	}
	return base
}

// renderNDJSON marshals findings exactly as the CLI does: one JSON object per
// line, each newline-terminated.
func renderNDJSON(t *testing.T, findings []scanner.Finding) string {
	t.Helper()

	var b strings.Builder
	for _, f := range findings {
		line, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("marshal finding: %v", err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// repoRoot walks up from the test's working directory to the directory holding
// go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (no go.mod found)")
		}
		dir = parent
	}
}

// chdir switches to dir for the duration of the test, restoring the original
// working directory on cleanup.
func chdir(t *testing.T, dir string) {
	t.Helper()

	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}
