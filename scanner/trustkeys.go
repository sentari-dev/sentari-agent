// Trusted ed25519 public keys for server-pushed signed data.
//
// Trust is bootstrapped at /register time: the server returns its
// license-map signing pubkey in the register response and the agent
// persists it to ``<certDir>/license_map_trust.json``.  On every
// subsequent startup ``main_enterprise.go`` loads that file and calls
// ``RegisterTrustedMapKey`` with the learned key.  Trust rides on the
// same TLS-fingerprint anchor the cert-issuance flow uses — an
// attacker who could inject a forged pubkey at register time could
// also mint a forged client cert, so nothing is gained by adding a
// compile-time pin on top.
//
// ``pinnedMapPubKeys`` stays empty in production.  It remains as an
// optional compile-time override for air-gapped deployments that
// want to bake a specific pubkey into the agent binary and refuse
// any key delivered at register time.
//
// For local development, the SENTARI_TRUSTED_MAP_PUBKEYS environment
// variable can inject additional keys at startup (comma-separated
// "key_id:base64pubkey" entries).  Intended for running the agent
// against ``make server-dev`` before the agent has registered.

package scanner

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
)

// pinnedMapPubKeys are keys compiled into the agent binary.  In the
// default production flow this stays empty — trust bootstraps at
// /register time (see package comment).  Air-gapped or extra-paranoid
// deployments can populate this slice with
// {KeyID: "...", B64: "..."} entries so the agent trusts only keys
// present at build time and rejects anything delivered at runtime.
var pinnedMapPubKeys = []pinnedKey{
	// {KeyID: "primary", B64: "…32-byte raw pubkey, base64-encoded…"},
}

type pinnedKey struct {
	KeyID string
	B64   string
}

func init() {
	for _, pk := range pinnedMapPubKeys {
		if raw, err := base64.StdEncoding.DecodeString(pk.B64); err == nil {
			RegisterTrustedMapKey(pk.KeyID, ed25519.PublicKey(raw))
		}
	}

	// Dev/CI override.  Logged-visible to operators if set.
	if env := os.Getenv("SENTARI_TRUSTED_MAP_PUBKEYS"); env != "" {
		for _, entry := range strings.Split(env, ",") {
			entry = strings.TrimSpace(entry)
			id, b64, ok := strings.Cut(entry, ":")
			if !ok {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
			if err != nil {
				continue
			}
			RegisterTrustedMapKey(strings.TrimSpace(id), ed25519.PublicKey(raw))
		}
	}
}
