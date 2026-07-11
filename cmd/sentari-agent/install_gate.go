//go:build enterprise

package main

import (
	"encoding/json"

	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/installgate"
)

// pipScopeFromConfig translates the operator's [install_gate]
// python_scope INI value into the writer's typed scope.  Empty
// or unrecognised → “user“ (laptop default), matching the
// design-doc §4.1 default for non-server hosts.
func pipScopeFromConfig(s string) installgate.PipScope {
	switch s {
	case "system":
		return installgate.PipScopeSystem
	default:
		return installgate.PipScopeUser
	}
}

// npmScopeFromConfig is the npm-side parallel of pipScopeFromConfig.
// Same defaulting story — empty / unrecognised → user.
func npmScopeFromConfig(s string) installgate.NpmScope {
	switch s {
	case "system":
		return installgate.NpmScopeSystem
	default:
		return installgate.NpmScopeUser
	}
}

// mavenScopeFromConfig is the Maven-side parallel of
// pipScopeFromConfig.  System scope is a soft no-op when MAVEN_HOME
// is unset — that decision lives downstream in MavenPath.
func mavenScopeFromConfig(s string) installgate.MavenScope {
	switch s {
	case "system":
		return installgate.MavenScopeSystem
	default:
		return installgate.MavenScopeUser
	}
}

// nugetScopeFromConfig is the NuGet-side parallel.  System scope
// is a soft no-op on POSIX (no system-wide NuGet config dir);
// that decision lives downstream in NuGetPath.
func nugetScopeFromConfig(s string) installgate.NuGetScope {
	switch s {
	case "system":
		return installgate.NuGetScopeSystem
	default:
		return installgate.NuGetScopeUser
	}
}

// uvScopeFromConfig — Astral's uv has user + system config paths.
// Same defaulting story as the others: empty / unrecognised → user.
func uvScopeFromConfig(s string) installgate.UvScope {
	switch s {
	case "system":
		return installgate.UvScopeSystem
	default:
		return installgate.UvScopeUser
	}
}

// pdmScopeFromConfig — pdm has no system-wide config path; the
// system enum value soft-no-ops downstream in PdmPath.  Kept for
// symmetry with the other scope helpers.
func pdmScopeFromConfig(s string) installgate.PdmScope {
	switch s {
	case "system":
		return installgate.PdmScopeSystem
	default:
		return installgate.PdmScopeUser
	}
}

// gradleScopeFromConfig — System soft-no-ops downstream in
// GradlePath when GRADLE_HOME is unset.
func gradleScopeFromConfig(s string) installgate.GradleScope {
	switch s {
	case "system":
		return installgate.GradleScopeSystem
	default:
		return installgate.GradleScopeUser
	}
}

// sbtScopeFromConfig — System soft-no-ops downstream in SbtPath
// when SBT_HOME is unset.
func sbtScopeFromConfig(s string) installgate.SbtScope {
	switch s {
	case "system":
		return installgate.SbtScopeSystem
	default:
		return installgate.SbtScopeUser
	}
}

// yarnBerryScopeFromConfig — Yarn Berry has no system-wide config
// path; system enum value soft-no-ops downstream.
func yarnBerryScopeFromConfig(s string) installgate.YarnBerryScope {
	switch s {
	case "system":
		return installgate.YarnBerryScopeSystem
	default:
		return installgate.YarnBerryScopeUser
	}
}

// envelopeKeyID extracts the “key_id“ field from a verified
// signed envelope's outer wrapper.  The signature itself was
// validated upstream in scanner.VerifyInstallGateEnvelope, so
// this is a safe re-decode for marker bookkeeping — we are not
// re-trusting the bytes, just lifting the already-verified key_id
// for embedding in the rendered config's “signed=“ marker.
//
// Falls back to “"primary"“ only when the envelope is malformed
// (which can't happen given the upstream verify) so the audit
// trail stays internally consistent rather than blank.
func envelopeKeyID(envelope []byte) string {
	var meta struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(envelope, &meta); err == nil && meta.KeyID != "" {
		return meta.KeyID
	}
	return "primary"
}

// installGateApplyOptions packages the per-ecosystem scope decisions
// from agent.conf into a single ApplyOptions struct.  Used both when
// applying a verified policy map (caller fills in marker) and when
// removing all configs on disable transitions (RemoveAll uses an
// empty marker — writers don't reference Marker on the no-endpoint
// removal branch).
func installGateApplyOptions(cfg config.AgentConfig, marker installgate.MarkerFields) installgate.ApplyOptions {
	return installgate.ApplyOptions{
		Marker:         marker,
		PipScope:       pipScopeFromConfig(cfg.InstallGate.PythonScope),
		NpmScope:       npmScopeFromConfig(cfg.InstallGate.NodeScope),
		MavenScope:     mavenScopeFromConfig(cfg.InstallGate.MavenScope),
		NuGetScope:     nugetScopeFromConfig(cfg.InstallGate.NuGetScope),
		UvScope:        uvScopeFromConfig(cfg.InstallGate.UvScope),
		PdmScope:       pdmScopeFromConfig(cfg.InstallGate.PdmScope),
		GradleScope:    gradleScopeFromConfig(cfg.InstallGate.GradleScope),
		SbtScope:       sbtScopeFromConfig(cfg.InstallGate.SbtScope),
		YarnBerryScope: yarnBerryScopeFromConfig(cfg.InstallGate.YarnBerryScope),
	}
}

// debounceThreshold reports the configured consecutive-disable threshold,
// or 1 when no debouncer is present (the one-shot --upload path tears down
// on a single signal).
func debounceThreshold(d *comms.InstallGateDisableDebouncer) int {
	if d == nil {
		return 1
	}
	return d.Threshold()
}
