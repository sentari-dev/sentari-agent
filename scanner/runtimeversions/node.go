package runtimeversions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// Node binaries embed the `node-vX.Y.Z` marker in .rodata. The old detector
// read only the first 16 MiB, but modern builds (v20+, v24) are 80–180 MiB and
// place the marker ~20–26 MiB in, so that cap silently missed them. We instead
// stream the file in bounded windows (constant memory) and search each window,
// carrying a small overlap so the marker is never split across a chunk
// boundary. A generous hard ceiling guards against pathological reads.
const (
	_nodeReadChunk   = 8 * 1024 * 1024   // streaming window size
	_nodeReadCeiling = 512 * 1024 * 1024 // never read past this many bytes
	// Overlap kept between windows — must exceed the longest possible marker
	// ("node-v" + three numeric components) so a marker straddling a window
	// boundary is reassembled in the next iteration.
	_nodeMarkerOverlap = 64

	// maxNodeSymlinkHops bounds how many symlink indirections we resolve
	// before giving up. A single hop covers Homebrew (/usr/local/bin/node
	// -> Cellar). Debian/Ubuntu route node through update-alternatives as a
	// MULTI-hop chain (/usr/bin/node -> /etc/alternatives/node ->
	// /usr/bin/nodejs, and nodejs may itself be a versioned symlink), so a
	// 1-hop cap silently missed apt-installed Node. The bound (plus the
	// O_NOFOLLOW safeio read at every step) is what keeps this safe against
	// symlink cycles and attacker-planted chains — NOT the hop count itself.
	maxNodeSymlinkHops = 8
)

var nodeVersionRe = regexp.MustCompile(`node-v(\d+\.\d+\.\d+)`)

// DetectNodeBinary reads the binary at `path` and extracts the embedded
// `node-vX.Y.Z` marker. Returns (nil, nil) when the file is missing or
// no marker is found.
//
// If `path` is itself a symlink (common on macOS/Homebrew where
// /usr/local/bin/node points into the Cellar, or under
// update-alternatives on Debian/Ubuntu), this resolves up to
// maxNodeSymlinkHops levels of indirection and retries on each target.
// The Debian update-alternatives layout is a genuine multi-hop chain
// (/usr/bin/node -> /etc/alternatives/node -> /usr/bin/nodejs), so a
// single hop is not enough. InstallPath in the returned runtime is the
// ORIGINAL symlink path, so the dashboard shows where the user thinks
// node lives rather than the resolved Cellar / alternatives target.
func DetectNodeBinary(path string) (*InstalledRuntime, error) {
	return detectNodeBinaryWithLimit(path, path, maxNodeSymlinkHops)
}

func detectNodeBinaryWithLimit(originalPath, path string, redirectsLeft int) (*InstalledRuntime, error) {
	f, err := safeio.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		if errors.Is(err, safeio.ErrSymlink) && redirectsLeft > 0 {
			// safeio refuses to open a symlink leaf (O_NOFOLLOW), which is
			// the security guarantee we rely on. To reach the real binary we
			// resolve ONE hop here with os.Readlink and retry via safeio on
			// the target. Repeating this walks a bounded chain:
			//   Homebrew  : /usr/local/bin/node -> Cellar/.../node (1 hop)
			//   Debian    : /usr/bin/node -> /etc/alternatives/node
			//               -> /usr/bin/nodejs [-> versioned] (>=2 hops)
			// redirectsLeft bounds the walk so a symlink cycle or an
			// attacker-planted chain terminates (no infinite loop); the
			// eventual read is still the O_NOFOLLOW safeio.Open above.
			resolved, rerr := os.Readlink(path)
			if rerr != nil {
				return nil, nil
			}
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(path), resolved)
			}
			return detectNodeBinaryWithLimit(originalPath, resolved, redirectsLeft-1)
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Streaming search — node binaries are large and the marker can sit tens
	// of MiB in (see const doc). A bounded window + overlap keeps memory flat
	// while covering the whole file up to the ceiling.
	version, err := scanNodeVersion(io.LimitReader(f, _nodeReadCeiling))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if version == "" {
		return nil, nil
	}
	return &InstalledRuntime{
		Name:    RuntimeNode,
		Version: version,
		Cycle:   CycleFor(RuntimeNode, version),
		// InstallPath stays the ORIGINAL path (the caller's candidate) so
		// the dashboard shows where the user expects node to live, not
		// the resolved Cellar / nvm dir.
		InstallPath: originalPath,
	}, nil
}

// scanNodeVersion streams r in bounded windows and returns the first
// `node-vX.Y.Z` version found (or "" if none). The last _nodeMarkerOverlap
// bytes of each window are prepended to the next so a marker spanning a
// read boundary is still matched.
func scanNodeVersion(r io.Reader) (string, error) {
	return scanNodeVersionChunked(r, _nodeReadChunk)
}

// scanNodeVersionChunked is the testable core of scanNodeVersion with an
// injectable window size so tests can exercise the cross-boundary overlap
// without materializing multi-MiB inputs.
//
// Boundary correctness: nodeVersionRe's trailing `\d+` is greedy but can only
// consume digits present in the current haystack. If a read boundary splits a
// marker mid-patch-component so a window ends "…node-v20.11.5" (the trailing
// "0" of "20.11.50" only arriving in the NEXT window), a naive
// return-on-first-match yields a syntactically-complete but WRONG version
// ("20.11.5"). To avoid that, when a match ends exactly at the end of the
// current haystack AND more data may still follow, we DEFER: carry the whole
// marker region forward and only ACCEPT the match once a non-digit terminator
// (or EOF) confirms the final component is complete. On EOF a match ending at
// end-of-buffer is genuinely complete and is accepted.
func scanNodeVersionChunked(r io.Reader, chunkSize int) (string, error) {
	chunk := make([]byte, chunkSize)
	var carry []byte
	for {
		n, rerr := r.Read(chunk)
		atEOF := errors.Is(rerr, io.EOF)
		if n > 0 {
			hay := append(carry, chunk[:n]...)
			if loc := nodeVersionRe.FindSubmatchIndex(hay); loc != nil {
				// loc[0]:loc[1] = full match, loc[2]:loc[3] = version group.
				// Defer only when the match butts against the read boundary,
				// more data may follow, and the marker region is short enough
				// to be a plausible (un-truncated) version — the length bound
				// also caps carry growth and guarantees termination on
				// pathological all-digit input.
				if !atEOF && loc[1] == len(hay) && len(hay)-loc[0] <= _nodeMarkerOverlap {
					carry = append(carry[:0], hay[loc[0]:]...)
				} else {
					return string(hay[loc[2]:loc[3]]), nil
				}
			} else if len(hay) > _nodeMarkerOverlap {
				// No match: keep a small overlap so a marker straddling the
				// boundary is reassembled in the next window.
				carry = append(carry[:0], hay[len(hay)-_nodeMarkerOverlap:]...)
			} else {
				carry = append(carry[:0], hay...)
			}
		}
		if atEOF {
			// Flush: a deferred match reaching EOF is complete and accepted.
			if loc := nodeVersionRe.FindSubmatchIndex(carry); loc != nil {
				return string(carry[loc[2]:loc[3]]), nil
			}
			return "", nil
		}
		if rerr != nil {
			return "", rerr
		}
	}
}

// DetectAllNodes scans candidate binary paths.
func DetectAllNodes(ctx context.Context, paths []string) []InstalledRuntime {
	var out []InstalledRuntime
	for _, p := range paths {
		if ctx.Err() != nil {
			return out
		}
		rt, err := DetectNodeBinary(p)
		if err != nil || rt == nil {
			continue
		}
		out = append(out, *rt)
	}
	return out
}
