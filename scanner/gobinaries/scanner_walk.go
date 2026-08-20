package gobinaries

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
)

// maxBinariesPerEnv bounds how many candidate binaries a single Environment
// (one bin directory) may probe. Well past any real install directory; a
// value beyond it is truncated with a ScanError. A var so tests can lower it.
var maxBinariesPerEnv = 2048

// maxWalkDepth is the deepest a candidate file may sit below the Environment
// root and still be probed. Bin directories are flat; depth 2 admits the
// GOOS_GOARCH cross-compile subdirectory `go install` writes under
// $GOPATH/bin. Anything deeper is not a bin-dir layout.
const maxWalkDepth = 2

// scanBinDir walks one bin directory, probing each regular file for embedded
// Go module metadata. It mirrors the JVM plugin's bounded-walk discipline:
// per-step context cancellation, ShouldSkipDir pruning, a depth cap, a
// per-directory binary cap, and error collection (never propagated — one
// unreadable subdirectory must not stop the rest of the scan). ScanError
// timestamps are stamped here at the package boundary.
func scanBinDir(ctx context.Context, root string) ([]scanner.PackageRecord, []scanner.ScanError) {
	var (
		records  []scanner.PackageRecord
		errs     []scanner.ScanError
		probed   int
		cappedAt bool
	)

	walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			errs = append(errs, scanner.ScanError{
				Path:      path,
				EnvType:   EnvGoBinary,
				Error:     fmt.Sprintf("scan cancelled: %v", ctxErr),
				Timestamp: time.Now().UTC(),
			})
			return fs.SkipAll
		}
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      path,
				EnvType:   EnvGoBinary,
				Error:     fmt.Sprintf("walk: %v", err),
				Timestamp: time.Now().UTC(),
			})
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if path == root {
				return nil
			}
			if pathfilter.ShouldSkipDir(path) {
				return filepath.SkipDir
			}
			// Prune before descending below the depth a probeable file can
			// occupy: a directory at depth d holds files at depth d+1.
			if componentDepth(root, path) >= maxWalkDepth {
				return filepath.SkipDir
			}
			return nil
		}

		// Regular files only, within the depth cap.
		if componentDepth(root, path) > maxWalkDepth {
			return nil
		}
		// Windows Go binaries always carry the .exe extension; this cheap name
		// gate skips the thousands of non-binary files in a Program Files tree
		// before the more expensive open + magic-sniff in probeBinary. Unix Go
		// binaries are extensionless, so no name gate applies there. The gate
		// lives here at the walk (not in probeBinary) so probeBinary stays a
		// pure, cross-platform-testable probe over any candidate path.
		if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(path), ".exe") {
			return nil
		}
		if cappedAt {
			return fs.SkipAll
		}
		if probed >= maxBinariesPerEnv {
			cappedAt = true
			errs = append(errs, scanner.ScanError{
				Path:      root,
				EnvType:   EnvGoBinary,
				Error:     fmt.Sprintf("binary count exceeds cap of %d; remaining binaries skipped", maxBinariesPerEnv),
				Timestamp: time.Now().UTC(),
			})
			return fs.SkipAll
		}
		probed++

		recs, probeErrs := probeBinary(path)
		records = append(records, recs...)
		now := time.Now().UTC()
		for _, e := range probeErrs {
			if e.Timestamp.IsZero() {
				e.Timestamp = now
			}
			errs = append(errs, e)
		}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, scanner.ScanError{
			Path:      root,
			EnvType:   EnvGoBinary,
			Error:     fmt.Sprintf("walk root: %v", walkErr),
			Timestamp: time.Now().UTC(),
		})
	}
	return records, errs
}

// componentDepth reports how many path components separate child from root
// (a file directly inside root is depth 1). Returns a large sentinel if child
// is not under root, so a mis-rooted path is treated as too deep and skipped.
func componentDepth(root, child string) int {
	rel, err := filepath.Rel(root, child)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return 1 << 30
	}
	return len(strings.Split(rel, string(filepath.Separator)))
}
