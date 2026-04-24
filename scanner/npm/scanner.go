// Package npm is the scanner plugin for the Node.js / npm ecosystem.
// Emits one PackageRecord per package discovered under any
// ``node_modules`` directory the agent encounters during its
// filesystem walk.
//
// Coverage: npm classic (flat `node_modules/<pkg>/package.json`),
// yarn classic (same layout), pnpm in ``shamefully-hoist`` mode
// (same layout), and scoped packages
// (``node_modules/@scope/<pkg>/package.json``).
//
// Explicitly NOT covered in v1 (tracked on ROADMAP.md):
//
//   - pnpm default mode, where ``node_modules/<pkg>`` is a symlink
//     into ``node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>``.
//     safeio refuses to follow the symlink — resolving it safely
//     wants ``openat2 RESOLVE_BENEATH`` in safeio, which is a
//     standalone piece of work.  v1 therefore produces zero
//     records on pnpm non-hoisted projects; operators can either
//     set ``shamefully-hoist=true`` in .npmrc or wait for the v2
//     plugin iteration.
//
//   - yarn Plug'n'Play (``.pnp.cjs`` manifest with bundled
//     packages).  Requires parsing a generated JS manifest —
//     own sprint.
//
// Server-side ecosystem mapping: env_type="npm" → ecosystem="npm"
// (OSV / PURL convention).
package npm

import (
	"context"
	"fmt"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// EnvNpm is the env_type every record from this plugin carries.
// Kept in sync with the server-side ENV_TYPE_TO_ECOSYSTEM table.
const EnvNpm = "npm"

// layoutNodeModules is the tag every discovered node_modules
// Environment carries, so Scan() dispatches correctly.  Currently
// the only layout tag — v2 additions (pnpm-store, pnp) will
// introduce more.
const layoutNodeModules = "node_modules"

func init() {
	scanner.Register(Scanner{})
}

// Scanner implements scanner.MarkerScanner.  The plugin's
// discovery runs during the shared filesystem walk: Match()
// is called on every directory, and when the basename is
// ``node_modules`` we queue an Environment for it.
type Scanner struct{}

// EnvType — see EnvNpm.
func (Scanner) EnvType() string { return EnvNpm }

// Match claims any directory named ``node_modules`` as an npm
// scan root.  Returns Terminal=true so the walker doesn't descend
// into it further — the plugin handles the per-package walk
// itself during Scan(), which is both faster than letting the
// generic walker recurse and avoids false-positive matches from
// other plugins on paths like ``node_modules/.cache``.
func (Scanner) Match(dirPath, baseName string) scanner.MatchResult {
	if baseName != "node_modules" {
		return scanner.MatchResult{}
	}
	return scanner.MatchResult{
		Matched:  true,
		Terminal: true,
		Env: scanner.Environment{
			EnvType: EnvNpm,
			Name:    layoutNodeModules,
			Path:    dirPath,
		},
	}
}

// Scan walks one node_modules directory one level deep (scoped
// packages force a second level via the ``@scope/`` convention)
// and emits one PackageRecord per package whose package.json we
// can read safely.  Per-package failures (permission denied,
// malformed JSON, symlink-refused) surface as ScanErrors so
// operators can audit what was skipped; one bad package never
// aborts the whole tree.
func (Scanner) Scan(ctx context.Context, env scanner.Environment) ([]scanner.PackageRecord, []scanner.ScanError) {
	_ = ctx
	switch env.Name {
	case layoutNodeModules:
		return scanNodeModules(env.Path)
	default:
		// Loud-on-wiring-bug, same convention as the JVM plugin.
		return nil, []scanner.ScanError{{
			Path:      env.Path,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("unknown npm layout: %q", env.Name),
			Timestamp: time.Now().UTC(),
		}}
	}
}
