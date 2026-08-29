// Package hardening collects raw host security-configuration facts — the v4
// `hardening_observations` block of the agent scan payload (see
// docs/contracts/agent-scan-payload-v4.{md,json}). It reads keyword values
// directly out of config files, /proc, the Windows registry, and Apple plists;
// it NEVER shells out to sshd/fdesetup/defaults/auditpol/nft/CIS-CAT
// (constraint #7) and NEVER opens a network socket (constraint #4).
//
// Facts, not verdicts: each Observation carries only the named keyword value the
// server's hardening-v1 catalog consumes, the source path, and the SHA-256 of
// the parsed file (drift detection without the file body leaving the device —
// the v3 lockfiles pattern). An unreadable or absent source is emitted with a
// null value + an `error`, which the server scores as `unknown` — the agent
// never fabricates a value. Wrong-platform families are simply not emitted
// (the server derives `not_applicable`).
//
// Dormant by default: Collect returns nil unless the operator sets
// `[hardening] enabled = true`, matching the install-gate opt-in posture.
package hardening

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sort"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxObservations is the payload cap the contract enforces (schema maxItems).
// The collectors emit far fewer than this; the guard defends against a
// pathological host (e.g. a huge Include fan-out).
const maxObservations = 256

// Per-source read caps. Every read goes through safeio (symlink-refusing,
// size-bounded); these bound the specific hardening sources.
const (
	maxConfigFileSize int64 = 1 << 20  // sshd_config, login.defs, nginx.conf, …
	maxProcFileSize   int64 = 64 << 10 // /proc/sys/* scalars
	maxPlistFileSize  int64 = 4 << 20  // Apple plists
)

// Families (contract v1 vocabulary).
const (
	familyDiskEncryption = "disk_encryption"
	familySSH            = "ssh"
	familyTLS            = "tls"
	familyFirewall       = "firewall"
	familyAuthPolicy     = "auth_policy"
	familyAuditDaemon    = "audit_daemon"
	familyAutoUpdate     = "auto_update"
	familyScreenLock     = "screen_lock"
	familyKernel         = "kernel"
)

// Observation is one raw security-configuration fact. Its JSON shape is
// byte-compatible with the contract's HardeningObservation: `key` and `family`
// are required; `value` is null when the source was unreadable (paired with
// `error`); the provenance fields are omitted when absent.
type Observation struct {
	Key            string  `json:"key"`
	Family         string  `json:"family"`
	Value          *string `json:"value"`
	DefaultAssumed bool    `json:"default_assumed,omitempty"`
	SourcePath     *string `json:"source_path,omitempty"`
	SourceSHA256   *string `json:"source_sha256,omitempty"`
	Error          *string `json:"error,omitempty"`
}

// Collect runs the platform hardening collectors and returns the observation
// list. It returns nil when the feature is disabled (the default) so a dormant
// agent emits no v4 header and byte-identical v3 payloads.
func Collect(ctx context.Context, enabled bool) []Observation {
	if !enabled {
		return nil
	}
	obs := collectPlatform(ctx)
	if len(obs) > maxObservations {
		obs = obs[:maxObservations]
	}
	return obs
}

// guard runs a single family's collector under panic recovery: one malformed
// source must never abort the whole hardening pass (mirrors the v3 enrichment
// safeCall). On panic it emits an explicit `unknown` for every key the family
// owns rather than nil — a crashed collector must read as `unknown`
// (indeterminate), NOT `not_applicable` (which a silent nil would imply
// server-side: "this check doesn't apply to the host"). family is a family
// constant so the panic fallback can name the catalog keys.
func guard(family string, fn func() []Observation) (out []Observation) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("hardening collector panicked; emitting unknown", "family", family, "panic", r)
			keys := panicKeys(family)
			out = make([]Observation, 0, len(keys))
			for _, k := range keys {
				out = append(out, obsError(k, family, "", "collector panicked"))
			}
		}
	}()
	return fn()
}

// authPolicySlugs is the auth_policy v1 vocabulary (shared by the collector, the
// Windows unknown-ledger, and the panic fallback).
var authPolicySlugs = []string{
	"pass_max_days", "pass_min_days", "pass_min_len",
	"pass_min_class", "faillock_deny", "faillock_unlock_time",
}

// panicKeys returns the catalog keys a family's collector is responsible for, so
// guard can degrade a panic to explicit `unknown` observations for that family.
func panicKeys(family string) []string {
	prefix := func(slugs []string) []string {
		out := make([]string, len(slugs))
		for i, s := range slugs {
			out[i] = family + "." + s
		}
		return out
	}
	switch family {
	case familySSH:
		return prefix(sortedSlugs())
	case familyKernel:
		slugs := make([]string, 0, len(kernelSysctls))
		for s := range kernelSysctls {
			slugs = append(slugs, s)
		}
		sort.Strings(slugs)
		return prefix(slugs)
	case familyAuthPolicy:
		return prefix(authPolicySlugs)
	case familyScreenLock:
		return []string{familyScreenLock + ".enabled", familyScreenLock + ".timeout_secs"}
	case familyTLS:
		return []string{familyTLS + ".min_version", familyTLS + ".ciphers"}
	case familyDiskEncryption:
		return []string{familyDiskEncryption + ".root_encrypted"}
	case familyFirewall:
		return []string{familyFirewall + ".enabled"}
	case familyAuditDaemon:
		return []string{familyAuditDaemon + ".enabled"}
	case familyAutoUpdate:
		return []string{familyAutoUpdate + ".enabled"}
	default:
		return nil
	}
}

// strptr returns a pointer to s (JSON emits the string, not null).
func strptr(s string) *string { return &s }

// sha256Hex returns the lowercase 64-hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Emitted-field caps mirror the v4 contract (docs/contracts/agent-scan-payload-v4.json:
// value maxLength 2048, error maxLength 255). The agent clamps at emit time so it
// never ships a payload its OWN shipped schema would reject (the server also
// clamps defensively, but the agent must not depend on that).
const (
	maxValueLen = 2048
	maxErrorLen = 255
)

// clampRunes truncates s to at most n Unicode code points (JSON Schema maxLength
// counts code points), never splitting a multi-byte rune.
func clampRunes(s string, n int) string {
	if len(s) <= n { // byte length ≤ n ⇒ rune count ≤ n
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// obsValue builds a fact observation with a real value and file provenance.
func obsValue(key, family, value, sourcePath string, sha string) Observation {
	o := Observation{Key: key, Family: family, Value: strptr(clampRunes(value, maxValueLen)), SourcePath: strptr(sourcePath)}
	if sha != "" {
		o.SourceSHA256 = strptr(sha)
	}
	return o
}

// obsDefault builds a fact observation whose value is the documented platform
// default because the keyword was absent (default_assumed = true).
func obsDefault(key, family, value, sourcePath string, sha string) Observation {
	o := obsValue(key, family, value, sourcePath, sha)
	o.DefaultAssumed = true
	return o
}

// obsError builds an unreadable observation: null value + a short reason. The
// server scores it `unknown`.
func obsError(key, family, sourcePath, reason string) Observation {
	o := Observation{Key: key, Family: family, Value: nil, Error: strptr(clampRunes(reason, maxErrorLen))}
	if sourcePath != "" {
		o.SourcePath = strptr(sourcePath)
	}
	return o
}

// readSource reads a bounded config/proc/plist file through safeio and returns
// its bytes plus the lowercase-hex SHA-256. A read failure returns a short,
// classified reason string suitable for an Observation.error.
func readSource(path string, maxSize int64) (data []byte, sha string, reason string) {
	b, err := safeio.ReadFile(path, maxSize)
	if err != nil {
		return nil, "", classifyReadErr(err)
	}
	return b, sha256Hex(b), ""
}

// classifyReadErr maps a safeio/os read error to a short, PII-free reason.
func classifyReadErr(err error) string {
	switch {
	case err == nil:
		return ""
	case isNotExist(err):
		return "not found"
	case isPermission(err):
		return "permission denied"
	default:
		return "unreadable"
	}
}
