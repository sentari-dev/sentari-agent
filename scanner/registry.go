// Scanner plugin registry.  Every ecosystem is a plugin that registers
// itself at init(); the orchestrator in scanner.go iterates the registry
// instead of switching on an enum, so adding an ecosystem is a single
// Register() call with no edits to shared code.

package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
)

// scanRootKey keys the effective scan root on the run context.  Scanners
// that care about scope (dpkg, rpm — not useful on a scoped tempdir run)
// read it via ScanRootFromContext / IsFullSystemScan.  Scanners that
// don't care (windows_registry, pip, poetry, …) can ignore it.
type scanRootKey struct{}

// WithScanRoot returns a copy of ctx carrying the configured scan root.
// The Runner calls this once before dispatching discovery and scanning.
func WithScanRoot(ctx context.Context, root string) context.Context {
	return context.WithValue(ctx, scanRootKey{}, root)
}

// ScanRootFromContext returns the scan root stored on ctx, or "" if none.
func ScanRootFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(scanRootKey{}).(string); ok {
		return v
	}
	return ""
}

// IsFullSystemScan reports whether the scan root on ctx is the root of
// the filesystem (/, or a drive letter on Windows).  Used by RootScanners
// that wrap system-wide databases (dpkg, rpm) to opt out of scoped runs.
func IsFullSystemScan(ctx context.Context) bool {
	root := ScanRootFromContext(ctx)
	if root == "" {
		return false
	}
	clean := filepath.Clean(root)
	if clean == "/" {
		return true
	}
	if runtime.GOOS == "windows" && len(clean) <= 3 {
		return true
	}
	return false
}

// Environment is the unit of work produced by discovery and consumed by Scan.
// It's the contract between the walker/root-dispatch layer and the per-
// ecosystem parser.  A scanner is free to tuck internal state in Path/Name
// during Match() / DiscoverAll() and retrieve it during Scan().
type Environment struct {
	EnvType string
	Path    string
	Name    string
}

// Scanner is the base every plugin implements.  EnvType() is the stable
// identifier reported on PackageRecord.EnvType and used as the registry
// dedup key.  Scan() consumes an Environment previously produced by the
// same scanner's discovery method.
type Scanner interface {
	EnvType() string
	Scan(ctx context.Context, env Environment) ([]PackageRecord, []ScanError)
}

// MatchResult is the per-directory verdict from a MarkerScanner.
//   - Matched=true queues an Environment for scanning.
//   - Terminal=true tells the walker not to descend into dirPath (regardless
//     of Matched).  A terminal non-match is how a scanner says "this dir is
//     mine but nothing to scan here" (e.g., a dangling venv).
//   - Warning is an optional non-fatal diagnostic emitted into ScanResult.
//     Errors (e.g., dangling venv) surface this way without coupling Match
//     to the errors slice.
type MatchResult struct {
	Matched  bool
	Terminal bool
	Env      Environment
	Warning  *ScanError
}

// MarkerScanner is a Scanner whose discovery runs during the shared
// filesystem walk.  Match() is called on every directory the walker visits.
// See scanner.go for the walker itself.
type MarkerScanner interface {
	Scanner
	Match(dirPath, baseName string) MatchResult
}

// RootScanner is a Scanner whose discovery is independent of the walk —
// it reads a fixed path (dpkg status, rpmdb) or queries the OS (Windows
// registry).  DiscoverAll() is called once per scan run.
type RootScanner interface {
	Scanner
	DiscoverAll(ctx context.Context) ([]Environment, []ScanError)
}

var (
	regMu      sync.RWMutex
	registered []Scanner
)

// Register adds a scanner to the global registry.  Call from init().
// Panics on EnvType collision — duplicate registration is a programmer
// error, not a runtime condition worth hiding behind an error return.
func Register(s Scanner) {
	regMu.Lock()
	defer regMu.Unlock()
	for _, existing := range registered {
		if existing.EnvType() == s.EnvType() {
			panic(fmt.Sprintf("scanner: env_type %q already registered", s.EnvType()))
		}
	}
	registered = append(registered, s)
}

// RegisteredScanners returns a snapshot of all registered scanners in
// registration order.  Safe to call concurrently; the returned slice is
// a copy.  Intended for diagnostics and tests.
func RegisteredScanners() []Scanner {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Scanner, len(registered))
	copy(out, registered)
	return out
}

// markerScanners returns only the registered MarkerScanners, in
// registration order.
func markerScanners() []MarkerScanner {
	regMu.RLock()
	defer regMu.RUnlock()
	var out []MarkerScanner
	for _, s := range registered {
		if m, ok := s.(MarkerScanner); ok {
			out = append(out, m)
		}
	}
	return out
}

// rootScanners returns only the registered RootScanners, in registration
// order.
func rootScanners() []RootScanner {
	regMu.RLock()
	defer regMu.RUnlock()
	var out []RootScanner
	for _, s := range registered {
		if r, ok := s.(RootScanner); ok {
			out = append(out, r)
		}
	}
	return out
}

// scannerFor looks up a registered scanner by EnvType.  Returns nil if
// no scanner claims that type.
func scannerFor(envType string) Scanner {
	regMu.RLock()
	defer regMu.RUnlock()
	for _, s := range registered {
		if s.EnvType() == envType {
			return s
		}
	}
	return nil
}
