// Signed install-gate policy-map verification.
//
// Phase B of the install-gate feature.  The agent fetches the
// policy-map from the server as a signed envelope —
// {payload, signature, key_id} — and verifies the ed25519 signature
// against a pinned public key (learned at /register time, persisted
// alongside the mTLS certs) before treating any rule as authoritative.
// Per-ecosystem config writers consume the verified InstallGateMap
// in a follow-up change.
//
// Why a separate channel from the license-map and (future) vuln-map:
// the install-gate signing key is rotated independently — a key
// compromise on one channel must not bleed into the other two.
// Trust state per channel is keyed by ``key_id``; the registries are
// disjoint maps in this package so a misconfigured caller cannot
// accidentally share a key across channels.
//
// Canonical-JSON rules are identical to the license-map: sorted keys
// at every level, no insignificant whitespace, UTF-8 with non-ASCII
// preserved, HTML chars not escaped.  The ``canonicalJSON`` helper in
// ``signed_map.go`` is reused unchanged — Go's package-private
// linkage gives us that for free, and the server-side
// ``server/services/signing.py`` produces byte-identical output
// for the install-gate payload schema.

package scanner

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// MaxInstallGatePayloadBytes caps the canonical-JSON size of a
// policy-map payload.  Mirrors the server-side cap in
// ``server/services/signing.py``; an envelope larger than this is
// refused by the server signer too.
const MaxInstallGatePayloadBytes = 5 * 1024 * 1024 // 5 MiB

// trustedInstallGateKeys is the registry of ed25519 public keys the
// agent will accept as policy-map signers, keyed by ``key_id``.
// Populated by ``RegisterTrustedInstallGateKey`` (called from
// /register response handling) and never mutated on the hot path.
var trustedInstallGateKeys = map[string]ed25519.PublicKey{}

// RegisterTrustedInstallGateKey pins a public key under a given
// key_id.  Silently no-ops on invalid key length so a corrupted
// trust file cannot crash the agent at startup — the caller treats
// "no trusted key" as "install-gate unavailable" and skips config
// rewrites.
func RegisterTrustedInstallGateKey(keyID string, pub ed25519.PublicKey) {
	if len(pub) != ed25519.PublicKeySize {
		return
	}
	trustedInstallGateKeys[keyID] = pub
}

// TrustedInstallGateKeyIDs returns the list of pinned key IDs.
// Exported for diagnostics and dev tooling; not used on the hot path.
func TrustedInstallGateKeyIDs() []string {
	ids := make([]string, 0, len(trustedInstallGateKeys))
	for k := range trustedInstallGateKeys {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	return ids
}

// InstallGateEntry is one rule on the deny/allow list — flat enough
// that the per-ecosystem writers can iterate it without further
// schema knowledge.  Pointer fields are intentional — the server
// emits ``null`` (not the empty string) for "no value", and a
// non-pointer ``string`` would silently coerce ``null`` to the zero
// value, hiding the distinction between "unset" and "empty string"
// from downstream writers that may want to treat them differently.
type InstallGateEntry struct {
	Pattern      string  `json:"pattern"`
	VersionRange *string `json:"version_range"`
	Severity     string  `json:"severity"`
	Reason       *string `json:"reason"`
	ScopeEnvTag  *string `json:"scope_env_tag"`
	ExpiresAt    *string `json:"expires_at"`
}

// InstallGateEcosystemBlock is one ecosystem's rule set.  ``Mode`` is
// "deny_list" or "allow_list".  Empty ``Entries`` is meaningful —
// signals that any previously-applied config for this ecosystem
// should be reverted on the next sync.
type InstallGateEcosystemBlock struct {
	Mode    string             `json:"mode"`
	Entries []InstallGateEntry `json:"entries"`
}

// InstallGateMap is the verified policy-map payload.  Maps to the
// envelope shape produced by ``server/api/v1/agent.py:get_policy_map``.
//
// ``Version`` is the integer epoch of the most-recent ``updated_at``
// across active rules.  Agents skip the apply step when their cached
// version is already >= the incoming value, so the writers run only
// when something actually changed.
//
// ``ProxyEndpoints`` carries the per-ecosystem Sentari-Proxy URLs
// the writers will use to gate installs.  Empty for ecosystems the
// operator has not configured a proxy for; the writer treats empty
// as "no proxy override" and emits a no-op config.
type InstallGateMap struct {
	Version        int                                  `json:"version"`
	Ecosystems     map[string]InstallGateEcosystemBlock `json:"ecosystems"`
	ProxyEndpoints map[string]string                    `json:"proxy_endpoints"`
}

// VerifyInstallGateEnvelope parses + verifies a signed policy-map
// envelope and returns the inner ``InstallGateMap`` on success.
// Returns a typed error for any failure so callers can log without
// leaking internals.
//
// Size cap, signature, and basic schema checks are all enforced
// here.  Callers must not apply any payload that bypassed this
// function.
func VerifyInstallGateEnvelope(data []byte) (*InstallGateMap, error) {
	if len(data) == 0 {
		return nil, errors.New("install-gate envelope: empty input")
	}
	if len(data) > MaxInstallGatePayloadBytes {
		return nil, fmt.Errorf(
			"install-gate envelope: exceeds max size (%d > %d)",
			len(data), MaxInstallGatePayloadBytes,
		)
	}

	var env signedEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("install-gate envelope: malformed JSON: %w", err)
	}
	if len(env.Payload) == 0 || env.Signature == "" || env.KeyID == "" {
		return nil, errors.New("install-gate envelope: missing required field")
	}

	pub, ok := trustedInstallGateKeys[env.KeyID]
	if !ok {
		return nil, fmt.Errorf("install-gate envelope: unknown signing key_id %q", env.KeyID)
	}

	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("install-gate envelope: signature not base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("install-gate envelope: signature wrong length (%d)", len(sig))
	}

	// Re-canonicalise the payload so Go's map-iteration order does not
	// affect verification.  Reuses the package-private helper that the
	// license-map verifier has been using since Sprint 12; same byte
	// output as ``server/services/signing.py:canonical_json``.
	var asMap map[string]interface{}
	if err := json.Unmarshal(env.Payload, &asMap); err != nil {
		return nil, fmt.Errorf("install-gate envelope: payload not a JSON object: %w", err)
	}
	canonical, err := canonicalJSON(asMap)
	if err != nil {
		return nil, fmt.Errorf("install-gate envelope: canonicalize: %w", err)
	}

	if !ed25519.Verify(pub, canonical, sig) {
		return nil, errors.New("install-gate envelope: signature verification failed")
	}

	var m InstallGateMap
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		return nil, fmt.Errorf("install-gate envelope: payload schema: %w", err)
	}
	// ``Ecosystems`` is mandatory — the server always emits a key for
	// every supported ecosystem (with empty Entries when no rules
	// exist).  Missing entirely means we are reading something other
	// than a policy-map (or a forged but signed payload from a
	// compromised key).  Refuse rather than silently apply nothing.
	if m.Ecosystems == nil {
		return nil, errors.New("install-gate envelope: missing ecosystems field")
	}
	return &m, nil
}

// LoadVerifiedInstallGateFromFile reads a cached envelope from disk,
// verifies it, and returns ``(map, raw envelope bytes, nil)`` on
// success.  Returns:
//
//   - ``(nil, nil, nil)`` when the file does not exist (fresh install
//     — caller falls back to a network fetch).
//   - ``(nil, nil, err)`` on read errors and on verification failures
//     so the caller can log at warning level.  A tampered cache is
//     the expected signal to refuse to apply and re-fetch fresh.
//
// The read is bounded by ``MaxInstallGatePayloadBytes`` so a
// pathological cache file (filesystem corruption, hostile process
// with write access to the cache dir) cannot OOM the agent before
// the size check inside ``VerifyInstallGateEnvelope`` fires.
func LoadVerifiedInstallGateFromFile(path string) (*InstallGateMap, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("install-gate cache open: %w", err)
	}
	defer f.Close()

	// Read one byte past the cap so we can distinguish "exactly at
	// cap" (legal) from "over cap" (refuse).  ``VerifyInstallGateEnvelope``
	// re-applies the same cap defensively.
	data, err := io.ReadAll(io.LimitReader(f, MaxInstallGatePayloadBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("install-gate cache read: %w", err)
	}
	if len(data) > MaxInstallGatePayloadBytes {
		return nil, nil, fmt.Errorf(
			"install-gate cache exceeds max size (>%d bytes)",
			MaxInstallGatePayloadBytes,
		)
	}

	m, err := VerifyInstallGateEnvelope(data)
	if err != nil {
		return nil, nil, err
	}
	return m, data, nil
}

// SaveVerifiedInstallGateEnvelopeToFile persists the full signed
// envelope (not the decoded map) so the next load can re-verify
// rather than trust the on-disk decoded form.  File mode 0600 — the
// envelope embeds operator notes (the ``reason`` field on each rule)
// that may include incident IDs or upstream-vendor references.
func SaveVerifiedInstallGateEnvelopeToFile(path string, envelope []byte) error {
	if len(envelope) > MaxInstallGatePayloadBytes {
		return fmt.Errorf("install-gate envelope: exceeds max size")
	}
	return os.WriteFile(path, envelope, 0o600)
}
