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

	// MavenScope picks ``user`` (~/.m2/settings.xml) or ``system``
	// ($MAVEN_HOME/conf/settings.xml).  System scope is a soft
	// no-op when MAVEN_HOME is unset.
	MavenScope MavenScope

	// NuGetScope picks ``user`` (per-user NuGet.Config) or
	// ``system`` (Windows-only ``%ProgramData%\NuGet\Config\``
	// drop-in).  System scope is a soft no-op on POSIX where
	// NuGet has no system-wide config dir.
	NuGetScope NuGetScope

	// UvScope picks ``user`` or ``system`` ``uv.toml``.
	// Astral's uv has its own config namespace separate from
	// pip's; without this the install-gate covers ``uv pip
	// install`` only and silently mis-routes ``uv add`` /
	// ``uv sync``.
	UvScope UvScope

	// PdmScope picks ``user`` config.  pdm has no system-wide
	// config path so PdmScopeSystem is a soft no-op.
	PdmScope PdmScope

	// GradleScope picks ``user`` (~/.gradle/init.d) or ``system``
	// ($GRADLE_HOME/init.d).  System is a soft no-op when
	// GRADLE_HOME is unset.
	GradleScope GradleScope

	// SbtScope picks ``user`` (~/.sbt/repositories) or ``system``
	// ($SBT_HOME/conf/repositories).  System is a soft no-op
	// when SBT_HOME is unset.
	SbtScope SbtScope

	// YarnBerryScope picks ``user`` (~/.yarnrc.yml).  Yarn berry
	// has no system-wide config path so System is a soft no-op.
	YarnBerryScope YarnBerryScope
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
	Pip       WritePipResult
	Npm       WriteNpmResult
	Maven     WriteMavenResult
	NuGet     WriteNuGetResult
	Uv        WriteUvResult
	Pdm       WritePdmResult
	Gradle    WriteGradleResult
	Sbt       WriteSbtResult
	YarnBerry WriteYarnBerryResult
	// future: apt, yum
}

// AnyChanged reports whether any writer reported a change in
// either direction (created, rewritten, or removed).  Caller uses
// this to decide whether to log at info-level (something changed
// → operator wants to know) or debug-level (everything was a
// no-op → noise).
//
// Maven's and NuGet's ``SkippedOperator`` flags are intentionally
// not counted as a change — skipping is the steady-state outcome
// on hosts whose package configs predate enrolment and would
// otherwise spam info-level logs every cycle.  The orchestrator's
// caller surfaces SkippedOperator separately in audit / structured
// logs so operators still see it.
func (r ApplyResult) AnyChanged() bool {
	if r.Pip.Changed || r.Pip.Removed {
		return true
	}
	if r.Npm.Changed || r.Npm.Removed {
		return true
	}
	if r.Maven.Changed || r.Maven.Removed {
		return true
	}
	if r.NuGet.Changed || r.NuGet.Removed {
		return true
	}
	if r.Uv.Changed || r.Uv.Removed {
		return true
	}
	if r.Pdm.Changed || r.Pdm.Removed {
		return true
	}
	if r.Gradle.Changed || r.Gradle.Removed {
		return true
	}
	if r.Sbt.Changed || r.Sbt.Removed {
		return true
	}
	if r.YarnBerry.Changed || r.YarnBerry.Removed {
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

	mavenRes, err := WriteMaven(m, opts.MavenScope, opts.Marker)
	res.Maven = mavenRes
	if err != nil {
		errs = append(errs, fmt.Errorf("maven writer: %w", err))
	}

	nugetRes, err := WriteNuGet(m, opts.NuGetScope, opts.Marker)
	res.NuGet = nugetRes
	if err != nil {
		errs = append(errs, fmt.Errorf("nuget writer: %w", err))
	}

	uvRes, err := WriteUv(m, opts.UvScope, opts.Marker)
	res.Uv = uvRes
	if err != nil {
		errs = append(errs, fmt.Errorf("uv writer: %w", err))
	}

	pdmRes, err := WritePdm(m, opts.PdmScope, opts.Marker)
	res.Pdm = pdmRes
	if err != nil {
		errs = append(errs, fmt.Errorf("pdm writer: %w", err))
	}

	gradleRes, err := WriteGradle(m, opts.GradleScope, opts.Marker)
	res.Gradle = gradleRes
	if err != nil {
		errs = append(errs, fmt.Errorf("gradle writer: %w", err))
	}

	sbtRes, err := WriteSbt(m, opts.SbtScope, opts.Marker)
	res.Sbt = sbtRes
	if err != nil {
		errs = append(errs, fmt.Errorf("sbt writer: %w", err))
	}

	yarnBerryRes, err := WriteYarnBerry(m, opts.YarnBerryScope, opts.Marker)
	res.YarnBerry = yarnBerryRes
	if err != nil {
		errs = append(errs, fmt.Errorf("yarn-berry writer: %w", err))
	}

	// Future writers register here.  Each one returns its own
	// per-ecosystem result + (possibly) error; we collect both so
	// the caller logs a structured summary like
	// {pip:changed, npm:noop, maven:err}.

	return res, errs
}
