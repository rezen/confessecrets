package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/rezen/confessecrets/pkg/scanner"
)

func main() {
	os.Exit(run())
}

// run executes the scan and returns the process exit code: 0 = no findings,
// 1 = findings written, 2 = a fatal error occurred. It is a separate function
// so deferred cleanup (flushing/closing output) runs before the process exits.
func run() int {
	configPath := flag.String("config", "config.yaml", "scanner config")
	root := flag.String("path", ".", "file or directory to scan")
	outputPath := flag.String("output", "-", "output file, or - for stdout")
	repoConfig := flag.Bool("repo-config", true, "respect repo-local config (.confessecrets.yaml) found at repo roots")
	scanMode := flag.String("scan", "all", "what to scan: all, source (only source code), or config (only structured config, omit source code)")
	showFiltered := flag.Bool("show-filtered", false, "keep findings excluded by the config filter, marked filtered=true with a filtered_reason, instead of dropping them")
	flag.Parse()

	if *scanMode != "all" && *scanMode != "source" && *scanMode != "config" {
		return fail(fmt.Errorf("invalid -scan %q: want all, source, or config", *scanMode))
	}

	cfg, err := scanner.LoadConfig(*configPath)
	if err != nil {
		return fail(err)
	}

	set, err := scanner.CompileConfig(cfg)
	if err != nil {
		return fail(err)
	}

	out, closeOut, err := openOutput(*outputPath)
	if err != nil {
		return fail(err)
	}
	defer closeOut()

	writer := bufio.NewWriter(out)

	resolver := scanner.NewConfigResolver(cfg, set, *repoConfig, *root)

	hadFindings := false

	walkErr := scanner.Walk(*root, func(path string) error {
		effCfg, effSet := resolver.Resolve(path)

		if !scanner.ShouldScan(path, effCfg.Files) {
			return nil
		}

		if !scanModeAllows(*scanMode, path) {
			return nil
		}

		findings, err := scanner.ScanFile(path, effSet, scanner.ScanOptions{IncludeFiltered: *showFiltered})
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			return nil
		}

		for _, finding := range findings {
			// Filtered findings are informational only (shown via -show-filtered)
			// and do not count toward the "secrets found" exit status.
			if !finding.Filtered {
				hadFindings = true
			}

			line, err := json.Marshal(finding)
			if err != nil {
				return err
			}

			if _, err := writer.Write(line); err != nil {
				return err
			}

			if err := writer.WriteByte('\n'); err != nil {
				return err
			}
		}

		return nil
	})

	if err := writer.Flush(); err != nil {
		return fail(err)
	}

	if walkErr != nil {
		return fail(walkErr)
	}

	if hadFindings {
		return 1
	}

	return 0
}

// scanModeAllows reports whether path should be scanned under the given mode:
// "source" restricts to source-code files, "config" excludes them, and "all"
// permits everything.
func scanModeAllows(mode, path string) bool {
	switch mode {
	case "source":
		return scanner.IsSourceFile(path)
	case "config":
		return !scanner.IsSourceFile(path)
	default:
		return true
	}
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}

	return f, func() { _ = f.Close() }, nil
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, err)
	return 2
}
