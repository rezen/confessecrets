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
	flag.Parse()

	cfg, err := scanner.LoadConfig(*configPath)
	if err != nil {
		return fail(err)
	}

	rules, err := scanner.CompileRules(cfg.Rules)
	if err != nil {
		return fail(err)
	}

	out, closeOut, err := openOutput(*outputPath)
	if err != nil {
		return fail(err)
	}
	defer closeOut()

	writer := bufio.NewWriter(out)

	hadFindings := false

	walkErr := scanner.Walk(*root, func(path string) error {
		if !scanner.ShouldScan(path, cfg.Files) {
			return nil
		}

		findings, err := scanner.ScanFile(path, rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", path, err)
			return nil
		}

		for _, finding := range findings {
			hadFindings = true

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
