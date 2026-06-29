// Package version is the single source of truth for the confessecrets release
// version. Number is a const so any package can reference it directly
// (e.g. in scan output, User-Agent strings, or logs) without an import cycle.
package version

import (
	"runtime/debug"
	"strings"
)

// Number is the canonical release version. Bump this in the same commit you
// tag, keeping the tag and the const in lockstep:
//
//	# edit Number -> "0.0.3", commit, then:
//	git tag -a v0.0.3 -m "v0.0.3"
//
// It is a const so it can be referenced anywhere as version.Number. Because
// consts cannot be overridden by -ldflags, only the build metadata below is
// stamped at build time.
const Number = "0.0.6"

// Build metadata, stamped on release builds via -ldflags, e.g.:
//
//	go build -ldflags "\
//	  -X github.com/rezen/confessecrets/pkg/version.Commit=$(git rev-parse --short HEAD) \
//	  -X github.com/rezen/confessecrets/pkg/version.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
//	  ./cmd/confessecrets
var (
	Commit = ""
	Date   = ""
)

// String renders the full version line: the const Number plus whatever build
// metadata is available, falling back to the info Go embeds automatically for
// `go install module@version` or VCS checkouts.
func String() string {
	c, d := Commit, Date

	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "" {
					c = s.Value
					if len(c) > 12 {
						c = c[:12]
					}
				}
			case "vcs.time":
				if d == "" {
					d = s.Value
				}
			}
		}
	}

	out := "v" + Number
	if c != "" {
		out += " (" + strings.TrimSpace(c) + ")"
	}
	if d != "" {
		out += " " + d
	}
	return out
}
