// Package gobinaries inventories the module dependency lists that Go
// compilers embed inside every module-built executable. The Go toolchain
// writes the main module, the full transitive dependency graph, and the
// build settings into a dedicated data section of the binary; the standard
// library's debug/buildinfo reader recovers them by parsing the object-file
// container (ELF / PE / Mach-O). The plugin walks a fixed set of well-known
// unmanaged-install directories, probes each regular file, and emits one
// PackageRecord per embedded module.
//
// Read-only by construction: the agent never executes a scanned binary. It
// opens each candidate through the symlink-refusing safeio.Open and reads it
// with debug/buildinfo, which performs only bounded ReadAt calls over the
// file bytes. Non-Go files fail the buildinfo parse cleanly and are skipped.
package gobinaries

import (
	"context"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// EnvGoBinary is the env_type reported on every PackageRecord this plugin
// emits. The value is the stable wire literal the server maps to the Go
// ecosystem; it is also the registry dedup key.
const EnvGoBinary = "go_binary"

func init() {
	scanner.Register(Scanner{})
}

// Scanner implements scanner.Scanner and scanner.RootScanner. The zero value
// is usable — there is no per-scanner configuration; environment variables
// and discovery roots are read at DiscoverAll / Scan time.
type Scanner struct{}

// EnvType reports the env_type stamped on every record this plugin produces.
func (Scanner) EnvType() string { return EnvGoBinary }

// Scan walks the given Environment (a binary directory) and probes each
// regular file for embedded Go module metadata. Implemented in scanner_walk;
// the body lives alongside its bounded-walk helpers.
func (Scanner) Scan(ctx context.Context, env scanner.Environment) ([]scanner.PackageRecord, []scanner.ScanError) {
	return scanBinDir(ctx, env.Path)
}
