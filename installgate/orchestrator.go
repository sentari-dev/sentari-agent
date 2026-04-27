// Apply orchestration — runs all per-ecosystem writers against a
// verified policy-map and returns aggregated results suitable for
// structured logging.
//
// PR-3 ships pip only; npm / Maven / NuGet / apt / yum register
// here as no-ops via the same ``Apply`` entry point so the caller's
// code path doesn't change as ecosystems land.

package installgate

import (
	"fmt"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// ApplyOptions controls one ``Apply`` invocation.  Held as a
// struct because the per-ecosystem-scope decisions (pip user vs
// system, npm user vs system, …) accumulate fast and a positional
// signature would be unreadable by Phase D.
type ApplyOptions struct {
	// Marker is the version + signing-key + apply-time stamp
	// embedded at the top of every rendered config.  Same struct
	// the writers consume internally; built once per scan cycle.
	Marker MarkerFields

	// PipScope picks ``user`` or ``system`` config target for pip.
	// Defaults to ``user`` (laptop) when zero-valued; operators
	// running the agent as root on servers should set
	// ``system`` via the agent config.
	PipScope PipScope

	// NpmScope picks ``user`` or ``system`` ``.npmrc``.  Same
	// defaulting story as ``PipScope``.
	NpmScope NpmScope
}

// ApplyResult collects per-ecosystem outcomes.  One field per
// ecosystem the writer package supports; PR-3 has only Pip
// populated, the rest are zero-value placeholders for the
// follow-up writers.
//
// Why a struct instead of a map[string]any: callers want typed
// access ("did pip change?") for structured logging without
// reflection.  The trade-off is that every new ecosystem adds a
// field here, but that's the exact spot a reviewer should look at
// when a new writer lands.
type ApplyResult struct {
	Pip WritePipResult
	Npm WriteNpmResult
	// future: Maven WriteMavenResult; NuGet …
}

// AnyChanged reports whether any writer reported a change in
// either direction (created, rewritten, or removed).  Caller uses
// this to decide whether to log at info-level (something changed
// → operator wants to know) or debug-level (everything was a
// no-op → noise).
func (r ApplyResult) AnyChanged() bool {
	if r.Pip.Changed || r.Pip.Removed {
		return true
	}
	if r.Npm.Changed || r.Npm.Removed {
		return true
	}
	return false
}

// Apply runs every per-ecosystem writer against ``m`` and
// aggregates results.  Errors from individual writers are
// collected and returned as a slice — one writer's failure must
// not block another writer's success because the per-ecosystem
// failure modes are independent (pip failing because /etc is
// read-only doesn't mean we should skip npm).
//
// A nil policy map is a programmer error; we return immediately
// rather than silently no-op-ing every writer.
func Apply(m *scanner.InstallGateMap, opts ApplyOptions) (ApplyResult, []error) {
	var (
		res  ApplyResult
		errs []error
	)
	if m == nil {
		return res, []error{fmt.Errorf("installgate.Apply: nil policy map")}
	}

	pipRes, err := WritePip(m, opts.PipScope, opts.Marker)
	res.Pip = pipRes
	if err != nil {
		errs = append(errs, fmt.Errorf("pip writer: %w", err))
	}

	npmRes, err := WriteNpm(m, opts.NpmScope, opts.Marker)
	res.Npm = npmRes
	if err != nil {
		errs = append(errs, fmt.Errorf("npm writer: %w", err))
	}

	// Future writers register here.  Each one returns its own
	// per-ecosystem result + (possibly) error; we collect both so
	// the caller logs a structured summary like
	// {pip:changed, npm:noop, maven:err}.

	return res, errs
}
