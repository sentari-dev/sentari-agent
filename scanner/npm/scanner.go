// Package npm is the scanner plugin for the Node.js / npm ecosystem.
// Emits one PackageRecord per package discovered under any
// `node_modules` directory the agent encounters during its
// filesystem walk.
//
// Coverage: npm classic (flat `node_modules/<pkg>/package.json`),
// yarn classic (same layout), pnpm in `shamefully-hoist` mode
// (same layout), scoped packages
// (`node_modules/@scope/<pkg>/package.json`), the
// version-conflict nested layout where npm installs a private
// `node_modules` inside a package dir
// (`node_modules/a/node_modules/lodash`) — descended recursively,
// bounded by maxNestedNodeModulesDepth — and pnpm default mode
// via the virtual-store walk (see below).
//
// pnpm default mode: `node_modules/<pkg>` is a symlink into
// `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>`.  The plugin
// skips symlinked directory entries during its walk (see the
// symlink-handling note in parser.go), so those symlinks produce
// no records; instead scanPnpmStore walks the REAL package
// directories inside `node_modules/.pnpm/*/node_modules/<pkg>` and
// emits one record per package.  This gives default-mode INVENTORY
// coverage (every installed package is discovered) but NOT full
// symlink-resolving dep-tree fidelity — a store record carries the
// package identity, not its resolved edge back to whichever
// dependant symlinked it in.  Full fidelity still wants `openat2
// RESOLVE_BENEATH` in safeio plus a resolve-then-verify path that
// keeps a followed symlink target inside the node_modules root
// (tracked on ROADMAP.md); operators wanting the classic flat
// layout can still set `shamefully-hoist=true` in `.npmrc`.
//
// Explicitly NOT covered in v1 (tracked on ROADMAP.md):
//
//   - yarn Plug'n'Play (`.pnp.cjs` manifest with bundled
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
// `node_modules` we queue an Environment for it.
type Scanner struct{}

// EnvType — see EnvNpm.
func (Scanner) EnvType() string { return EnvNpm }

// Match claims any directory named `node_modules` as an npm
// scan root.  Returns Terminal=true so the walker doesn't descend
// into it further — the plugin handles the per-package walk
// itself during Scan(), which is both faster than letting the
// generic walker recurse and avoids false-positive matches from
// other plugins on paths like `node_modules/.cache`.
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
// packages force a second level via the `@scope/` convention, and
// version-conflict nested `node_modules` are descended recursively
// under a depth cap) and emits one PackageRecord per package whose
// package.json we can read safely.  Per-package failures
// (permission denied, malformed JSON, symlink-refused) surface as
// ScanErrors so operators can audit what was skipped; one bad
// package never aborts the whole tree.
func (Scanner) Scan(ctx context.Context, env scanner.Environment) ([]scanner.PackageRecord, []scanner.ScanError) {
	switch env.Name {
	case layoutNodeModules:
		return scanNodeModules(ctx, env.Path, 0)
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
