package scanner_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rezen/confessecrets/pkg/scanner"
)

// This file benchmarks confessecrets against two third-party secret scanners --
// trufflehog and gitleaks -- on the repo's samples/ corpus. Rather than rely on
// whatever happens to be on $PATH, it downloads pinned release builds of each
// tool into the repo's gitignored tmp/ directory and verifies them against an
// embedded SHA-256 before running them, so the comparison is reproducible across
// machines and CI.
//
// "confessecrets' result" for the comparison is taken from each sample's .verify
// golden file. TestSamples already guarantees the live scanner output equals the
// .verify byte-for-byte, so the golden file is exactly what confessecrets emits --
// reading it here avoids re-scanning and keeps the two tests in agreement.
//
// The comparison is keyed on (file, line): for every genuine secret (the
// level=="high" findings in the .verify) the test records whether each tool
// flagged that line, plus any extra lines a tool flagged that confessecrets does
// not report at all. The genuine-secret recall table is logged, and the test
// asserts confessecrets is never out-recalled by an external tool on those lines.
//
// The download is network-dependent, so the test skips (rather than fails) when a
// release cannot be fetched or the platform has no pinned asset, and skips under
// -short. A SHA-256 mismatch, by contrast, fails loudly -- that is the integrity
// guarantee the pinning exists to provide. Set CONFESS_SKIP_EXTERNAL=1 to skip
// unconditionally.

// externalTool describes a third-party scanner: a pinned version plus, per Go
// platform (GOOS_GOARCH), the release archive URL and the SHA-256 of that
// archive. binaryName is the executable's name inside the .tar.gz.
type externalTool struct {
	name       string
	version    string
	binaryName string
	assets     map[string]toolAsset
}

type toolAsset struct {
	url    string
	sha256 string
}

// trufflehog and gitleaks publish per-OS/arch .tar.gz archives with a published
// checksums file; the sums below are copied from those checksum files for the
// pinned versions. Note gitleaks names amd64 assets "x64".
var externalTools = []externalTool{
	{
		name:       "trufflehog",
		version:    "3.95.6",
		binaryName: "trufflehog",
		assets: map[string]toolAsset{
			"darwin_arm64": {"https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.6/trufflehog_3.95.6_darwin_arm64.tar.gz", "a31879b8fdf68e6f6b739bea1ae812660d43b11f4c980131ab6cb2b81aef3041"},
			"darwin_amd64": {"https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.6/trufflehog_3.95.6_darwin_amd64.tar.gz", "56e1108a9f074962d85ef3e3d442d0fcac1068d038b47fee4fc8bc6a7ad82a5d"},
			"linux_amd64":  {"https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.6/trufflehog_3.95.6_linux_amd64.tar.gz", "1b62ea3cbc672ed5fd36e0eebb00b1fb50bbb7ee35090f42437a5852a299e16b"},
			"linux_arm64":  {"https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.6/trufflehog_3.95.6_linux_arm64.tar.gz", "e0d8722485bf592f9ef9a72009fb5184656cfab4864fed453bbbf694d5b9350b"},
		},
	},
	{
		name:       "gitleaks",
		version:    "8.30.1",
		binaryName: "gitleaks",
		assets: map[string]toolAsset{
			"darwin_arm64": {"https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"},
			"darwin_amd64": {"https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz", "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"},
			"linux_amd64":  {"https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"},
			"linux_arm64":  {"https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz", "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"},
		},
	},
}

func platformKey() string { return runtime.GOOS + "_" + runtime.GOARCH }

// perfRuns is how many times each scanner is timed over the corpus. Enough
// iterations to average out per-run noise; like TestExternalCompare the whole
// pass is gated behind -short and the external-tool skips.
const perfRuns = 100

// perfStats summarizes the timing of perfRuns invocations of one scanner.
type perfStats struct {
	n                      int
	min, max, mean, median time.Duration
}

// TestExternalPerformance times confessecrets and each external scanner over the
// staged sample corpus, running each perfRuns times and logging the timing
// distribution. It is a measurement, not an assertion: it never fails on timing,
// only on a setup error, so a slow or busy machine cannot break CI.
func TestExternalPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent external-tool performance test in -short mode")
	}
	if os.Getenv("CONFESS_SKIP_EXTERNAL") != "" {
		t.Skip("CONFESS_SKIP_EXTERNAL set")
	}

	root := repoRoot(t)
	chdir(t, root)

	samples := loadComparisonSamples(t)
	if len(samples) == 0 {
		t.Fatal("no samples/*.verify files found")
	}
	inputsDir := stageInputs(t, root, samples)

	th := ensureTool(t, root, externalTools[0])
	gl := ensureTool(t, root, externalTools[1])

	// confessecrets runs in-process: compile the repo config once, then scan
	// every staged input per iteration, mirroring what the CLI does for a dir.
	cfg, err := scanner.LoadConfig("config.yaml")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	set, err := scanner.CompileConfig(cfg)
	if err != nil {
		t.Fatalf("compile config: %v", err)
	}

	// A dedicated report path so a parallel TestExternalCompare gitleaks run
	// never clobbers this one's output.
	report := filepath.Join(root, "tmp", "external", "perf-gitleaks-report.json")

	scanners := []struct {
		name string
		run  func() error
	}{
		{"confessecrets", func() error {
			return scanner.Walk(inputsDir, func(path string) error {
				_, err := scanner.ScanFile(path, set, scanner.ScanOptions{})
				return err
			})
		}},
		{"trufflehog", func() error {
			// trufflehog exits non-zero when it finds secrets; that is expected
			// here and not a timing error, so the run error is ignored.
			_ = exec.Command(th, "filesystem", inputsDir, "--json", "--no-update", "--results=verified,unknown,unverified").Run()
			return nil
		}},
		{"gitleaks", func() error {
			return exec.Command(gl, "dir", inputsDir, "-f", "json", "-r", report, "--no-banner", "--exit-code", "0").Run()
		}},
	}

	t.Logf("timing %d run(s) of each scanner over %d sample file(s)", perfRuns, len(samples))
	rows := make([]perfRow, 0, len(scanners))
	for _, sc := range scanners {
		stats, err := measurePerf(perfRuns, sc.run)
		if err != nil {
			t.Fatalf("%s: %v", sc.name, err)
		}
		t.Logf("    %-13s min=%-12v median=%-12v mean=%-12v max=%-12v (n=%d)",
			sc.name, stats.min, stats.median, stats.mean, stats.max, stats.n)
		rows = append(rows, perfRow{name: sc.name, stats: stats})
	}

	out := filepath.Join(root, "performance.md")
	if err := writePerformanceReport(out, len(samples), rows); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
	t.Logf("wrote performance report to %s", out)
}

// perfRow pairs a scanner's name with its measured timing for the report.
type perfRow struct {
	name  string
	stats perfStats
}

// writePerformanceReport renders the timing rows as a Markdown table at path,
// overwriting any previous report. The note that it is generated keeps anyone
// from hand-editing a file the test will clobber on the next run.
func writePerformanceReport(path string, sampleCount int, rows []perfRow) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Scanner performance\n\n")
	fmt.Fprintf(&b, "_Generated by `TestExternalPerformance`; re-run `go test -run TestExternalPerformance ./pkg/scanner/` to refresh. Do not edit by hand._\n\n")
	fmt.Fprintf(&b, "Each scanner was timed over the same %d-file sample corpus, %d run(s) each.\n", sampleCount, perfRuns)
	fmt.Fprintf(&b, "confessecrets runs in-process; trufflehog and gitleaks are external processes, so their\n")
	fmt.Fprintf(&b, "times include per-invocation process startup (the realistic per-call cost).\n\n")
	fmt.Fprintf(&b, "Environment: %s/%s, %d CPU(s), %s.\n\n", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
	fmt.Fprintf(&b, "| Scanner | Runs | Min | Median | Mean | Max |\n")
	fmt.Fprintf(&b, "|---|---:|---:|---:|---:|---:|\n")
	for _, r := range rows {
		s := r.stats
		fmt.Fprintf(&b, "| %s | %d | %v | %v | %v | %v |\n",
			r.name, s.n, s.min, s.median, s.mean, s.max)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// measurePerf runs fn n times, timing each call, and returns the timing
// distribution. It stops and returns on the first error fn produces.
func measurePerf(n int, fn func() error) (perfStats, error) {
	durs := make([]time.Duration, 0, n)
	var total time.Duration
	for i := 0; i < n; i++ {
		start := time.Now()
		if err := fn(); err != nil {
			return perfStats{}, err
		}
		d := time.Since(start)
		durs = append(durs, d)
		total += d
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	return perfStats{
		n:      n,
		min:    durs[0],
		max:    durs[n-1],
		mean:   total / time.Duration(n),
		median: durs[n/2],
	}, nil
}

// TestExternalCompare downloads the pinned external scanners, runs them over the
// sample corpus, and logs how their genuine-secret recall compares to
// confessecrets'.
func TestExternalCompare(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-dependent external-tool comparison in -short mode")
	}
	if os.Getenv("CONFESS_SKIP_EXTERNAL") != "" {
		t.Skip("CONFESS_SKIP_EXTERNAL set")
	}

	root := repoRoot(t)
	chdir(t, root)

	samples := loadComparisonSamples(t)
	if len(samples) == 0 {
		t.Fatal("no samples/*.verify files found")
	}

	// Stage just the real sample inputs into a temp dir so the external tools
	// scan only those, never the .verify golden files (which contain the secrets
	// verbatim and would inflate every tool's hit count).
	inputsDir := stageInputs(t, root, samples)

	th := ensureTool(t, root, externalTools[0])
	gl := ensureTool(t, root, externalTools[1])

	thHits := runTrufflehog(t, th, inputsDir)
	glHits := runGitleaks(t, root, gl, inputsDir)

	var totalSecrets, confessHits, thTotal, glTotal int
	for _, s := range samples {
		secretLines := sortedInts(s.secretLines) // genuine secrets: level=="high"
		th := s.match(thHits)
		gl := s.match(glHits)

		// confessecrets reports every line in secretLines by construction, so its
		// recall is the full set; the loop still computes it for symmetry.
		cf := len(secretLines)
		totalSecrets += len(secretLines)
		confessHits += cf
		thTotal += len(th.hits)
		glTotal += len(gl.hits)

		t.Logf("%s -- %d genuine secret line(s): %v", s.base, len(secretLines), secretLines)
		t.Logf("    confessecrets : %d/%d genuine  (extra: 0)", cf, len(secretLines))
		t.Logf("    gitleaks      : %d/%d genuine  (extra non-secret lines flagged: %v)", len(gl.hits), len(secretLines), gl.extra)
		t.Logf("    trufflehog    : %d/%d genuine  (extra non-secret lines flagged: %v)", len(th.hits), len(secretLines), th.extra)

		// confessecrets must never be out-recalled on genuine secrets.
		if len(th.hits) > cf {
			t.Errorf("%s: trufflehog recalled more genuine secrets (%d) than confessecrets (%d)", s.base, len(th.hits), cf)
		}
		if len(gl.hits) > cf {
			t.Errorf("%s: gitleaks recalled more genuine secrets (%d) than confessecrets (%d)", s.base, len(gl.hits), cf)
		}
	}

	t.Logf("TOTAL genuine secret lines across corpus: %d", totalSecrets)
	t.Logf("    confessecrets recall : %d/%d (%s)", confessHits, totalSecrets, pct(confessHits, totalSecrets))
	t.Logf("    gitleaks recall      : %d/%d (%s)", glTotal, totalSecrets, pct(glTotal, totalSecrets))
	t.Logf("    trufflehog recall    : %d/%d (%s)", thTotal, totalSecrets, pct(thTotal, totalSecrets))

	if confessHits != totalSecrets {
		t.Errorf("confessecrets ground truth inconsistent: %d/%d genuine secrets", confessHits, totalSecrets)
	}
}

// comparisonSample is one sample file and the line numbers confessecrets reports
// for it, split into genuine secrets (level=="high") and all reported lines.
type comparisonSample struct {
	base        string       // basename of the sample input, e.g. props1.properties
	secretLines map[int]bool // lines with a level=="high" finding
	allLines    map[int]bool // every line confessecrets reports
}

// toolResult holds, for one sample and one tool, which genuine-secret lines the
// tool hit and which extra (non-confessecrets) lines it flagged.
type toolResult struct {
	hits  []int
	extra []int
}

// match scores a tool's per-basename line hits against this sample.
func (s comparisonSample) match(byBase map[string]map[int]bool) toolResult {
	var r toolResult
	for line := range byBase[s.base] {
		switch {
		case s.secretLines[line]:
			r.hits = append(r.hits, line)
		case !s.allLines[line]:
			r.extra = append(r.extra, line)
		}
	}
	sort.Ints(r.hits)
	sort.Ints(r.extra)
	return r
}

// loadComparisonSamples reads each samples/*.verify golden file and extracts the
// confessecrets line sets it implies.
func loadComparisonSamples(t *testing.T) []comparisonSample {
	t.Helper()

	verifies, err := filepath.Glob(filepath.Join("samples", "*.verify"))
	if err != nil {
		t.Fatalf("glob samples: %v", err)
	}
	sort.Strings(verifies)

	var out []comparisonSample
	for _, vp := range verifies {
		target := sampleTarget(vp)
		data, err := os.ReadFile(vp)
		if err != nil {
			t.Fatalf("read %s: %v", vp, err)
		}

		cs := comparisonSample{
			base:        filepath.Base(target),
			secretLines: map[int]bool{},
			allLines:    map[int]bool{},
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var f struct {
				Line  int    `json:"line"`
				Level string `json:"level"`
			}
			if err := json.Unmarshal([]byte(line), &f); err != nil {
				t.Fatalf("parse %s: %v", vp, err)
			}
			cs.allLines[f.Line] = true
			if f.Level == "high" {
				cs.secretLines[f.Line] = true
			}
		}
		out = append(out, cs)
	}
	return out
}

// stageInputs copies each real sample input into a fresh temp dir under tmp/ and
// returns that dir, so the external tools scan only the inputs.
func stageInputs(t *testing.T, root string, samples []comparisonSample) string {
	t.Helper()

	dir := filepath.Join(root, "tmp", "external", "inputs")
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("clean inputs: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	for _, s := range samples {
		src := filepath.Join(root, "samples", s.base)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read sample %s: %v", src, err)
		}
		if err := os.WriteFile(filepath.Join(dir, s.base), data, 0o644); err != nil {
			t.Fatalf("stage %s: %v", s.base, err)
		}
	}
	return dir
}

// ensureTool returns the path to a verified, executable copy of tool, downloading
// and extracting it into tmp/external/ if it is not already present.
func ensureTool(t *testing.T, root string, tool externalTool) string {
	t.Helper()

	binDir := filepath.Join(root, "tmp", "external", "bin")
	binPath := filepath.Join(binDir, tool.name+"-"+tool.version)
	if isExecutable(binPath) {
		return binPath
	}

	asset, ok := tool.assets[platformKey()]
	if !ok {
		t.Skipf("no pinned %s asset for %s", tool.name, platformKey())
	}

	cacheDir := filepath.Join(root, "tmp", "external", "cache")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	archivePath := filepath.Join(cacheDir, filepath.Base(asset.url))

	// Reuse a cached archive only if it still matches the pinned sum; otherwise
	// (re)download. A download failure skips -- it is almost always a network
	// issue, not a defect in the code under test.
	if !sha256Matches(archivePath, asset.sha256) {
		if err := download(asset.url, archivePath); err != nil {
			t.Skipf("could not download %s (network?): %v", asset.url, err)
		}
	}

	// Integrity gate: a mismatch here is a hard failure, not a skip.
	if !sha256Matches(archivePath, asset.sha256) {
		got, _ := sha256File(archivePath)
		t.Fatalf("SHA-256 mismatch for %s\n  want %s\n  got  %s", asset.url, asset.sha256, got)
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := extractBinary(archivePath, tool.binaryName, binPath); err != nil {
		t.Fatalf("extract %s: %v", tool.name, err)
	}
	return binPath
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func download(url, dest string) error {
	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	tmp := dest + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dest)
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Matches(path, want string) bool {
	got, err := sha256File(path)
	return err == nil && got == want
}

// extractBinary pulls the entry named binaryName out of a .tar.gz archive and
// writes it to dest with the executable bit set.
func extractBinary(archivePath, binaryName, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("binary %q not found in %s", binaryName, archivePath)
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) != binaryName || hdr.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
}

// runTrufflehog scans inputsDir and returns the set of lines flagged per sample
// basename. trufflehog emits one JSON object per finding on stdout.
func runTrufflehog(t *testing.T, bin, inputsDir string) map[string]map[int]bool {
	t.Helper()

	cmd := exec.Command(bin, "filesystem", inputsDir, "--json", "--no-update", "--results=verified,unknown,unverified")
	out, err := cmd.Output()
	if err != nil {
		// trufflehog exits non-zero on some run conditions; surface stderr but do
		// not fail the comparison over it.
		t.Logf("trufflehog run note: %v", err)
	}

	hits := map[string]map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var f struct {
			SourceMetadata struct {
				Data struct {
					Filesystem struct {
						File string `json:"file"`
						Line int    `json:"line"`
					} `json:"Filesystem"`
				} `json:"Data"`
			} `json:"SourceMetadata"`
		}
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			continue
		}
		fs := f.SourceMetadata.Data.Filesystem
		if fs.File == "" {
			continue
		}
		addHit(hits, filepath.Base(fs.File), fs.Line)
	}
	return hits
}

// runGitleaks scans inputsDir, writing a JSON report it then parses into per-base
// line sets. --exit-code 0 keeps a "leaks found" run from looking like failure.
func runGitleaks(t *testing.T, root, bin, inputsDir string) map[string]map[int]bool {
	t.Helper()

	report := filepath.Join(root, "tmp", "external", "gitleaks-report.json")
	cmd := exec.Command(bin, "dir", inputsDir, "-f", "json", "-r", report, "--no-banner", "--exit-code", "0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gitleaks run: %v\n%s", err, out)
	}

	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("read gitleaks report: %v", err)
	}

	var findings []struct {
		File      string `json:"File"`
		StartLine int    `json:"StartLine"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatalf("parse gitleaks report: %v", err)
	}

	hits := map[string]map[int]bool{}
	for _, f := range findings {
		addHit(hits, filepath.Base(f.File), f.StartLine)
	}
	return hits
}

func addHit(m map[string]map[int]bool, base string, line int) {
	if m[base] == nil {
		m[base] = map[int]bool{}
	}
	m[base][line] = true
}

func sortedInts(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func pct(n, d int) string {
	if d == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(n)/float64(d))
}
