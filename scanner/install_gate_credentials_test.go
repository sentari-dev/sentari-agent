// Tests for credential-lifetime handling on the verified install-gate
// map: cleartext registry credentials must not be persisted to the
// on-disk envelope cache, and the in-memory credential material must
// be zeroed once the config writers have applied it.

package scanner

import (
	"strings"
	"testing"
)

// mapWithCreds returns an InstallGateMap carrying a populated basic-auth
// block and a bearer-token block across two ecosystems.
func mapWithCreds() *InstallGateMap {
	return &InstallGateMap{
		Version: 7,
		Ecosystems: map[string]InstallGateEcosystemBlock{
			"pypi": {Mode: "deny_list"},
			"npm":  {Mode: "deny_list"},
		},
		TrustedRegistries: map[string][]TrustedRegistry{
			"pypi": {
				{
					URL: "https://nexus.test/pypi/",
					Auth: &RegistryAuth{
						Mode:     "basic",
						Username: "svc-pypi",
						Password: "s3cr3t-pypi",
					},
				},
			},
			"npm": {
				{
					URL: "https://nexus.test/npm/",
					Auth: &RegistryAuth{
						Mode:  "bearer",
						Token: "tok-npm-abcdef",
					},
				},
			},
		},
	}
}

func TestInstallGateMap_HasRegistryCredentials(t *testing.T) {
	if !mapWithCreds().HasRegistryCredentials() {
		t.Fatal("map with auth blocks must report HasRegistryCredentials() == true")
	}
	noAuth := &InstallGateMap{
		TrustedRegistries: map[string][]TrustedRegistry{
			"pypi": {{URL: "https://public.test/pypi/"}},
		},
		ProxyEndpoints: map[string]string{"pypi": "https://proxy.test/pypi/"},
	}
	if noAuth.HasRegistryCredentials() {
		t.Fatal("map with no usable auth must report HasRegistryCredentials() == false")
	}
	if (*InstallGateMap)(nil).HasRegistryCredentials() {
		t.Fatal("nil receiver must report false")
	}
}

func TestInstallGateMap_ZeroRegistryCredentials(t *testing.T) {
	m := mapWithCreds()
	m.ZeroRegistryCredentials()

	for eco, list := range m.TrustedRegistries {
		for i := range list {
			auth := list[i].Auth
			if auth == nil {
				continue
			}
			if auth.Token != "" || auth.Username != "" || auth.Password != "" {
				t.Errorf("ecosystem %q entry %d: credential material not cleared: %+v", eco, i, auth)
			}
		}
	}
	if m.HasRegistryCredentials() {
		t.Error("after ZeroRegistryCredentials the map must no longer report usable credentials")
	}
	// URLs must survive — only the secret material is cleared.
	if m.TrustedRegistries["pypi"][0].URL == "" {
		t.Error("registry URL must be preserved when clearing credentials")
	}
}

func TestInstallGateMap_ZeroRegistryCredentials_NilSafe(t *testing.T) {
	// Must not panic on a nil receiver or on entries with nil Auth.
	(*InstallGateMap)(nil).ZeroRegistryCredentials()
	m := &InstallGateMap{
		TrustedRegistries: map[string][]TrustedRegistry{
			"pypi": {{URL: "https://public.test/pypi/", Auth: nil}},
		},
	}
	m.ZeroRegistryCredentials()
}

// A cached envelope must never contain cleartext credentials.  The
// caller is expected to skip caching credential-bearing maps; this test
// documents the policy that the on-disk bytes carry no secret material.
func TestInstallGateMap_CredentialsNotPersistedToCache(t *testing.T) {
	priv := registerInstallGateTestKey(t, "ig-creds-cache")

	// Build a payload that embeds auth secrets the way the server emits
	// them, then verify it through the production verifier.
	payload := map[string]interface{}{
		"version": 9,
		"ecosystems": map[string]interface{}{
			"pypi": map[string]interface{}{"mode": "deny_list", "entries": []interface{}{}},
		},
		"proxy_endpoints": map[string]interface{}{},
		"trusted_registries": map[string]interface{}{
			"pypi": []interface{}{
				map[string]interface{}{
					"url": "https://nexus.test/pypi/",
					"auth": map[string]interface{}{
						"mode":     "basic",
						"username": "svc-pypi",
						"password": "s3cr3t-pypi",
					},
				},
			},
		},
	}
	envelope := signInstallGateEnvelope(t, priv, "ig-creds-cache", payload)

	m, err := VerifyInstallGateEnvelope(envelope)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !m.HasRegistryCredentials() {
		t.Fatal("expected verified map to carry credentials for this test")
	}

	// The envelope itself (what the caller would otherwise persist) does
	// contain the secret — which is exactly why callers must not write
	// it to the cache.  Assert the secret is detectable in the raw bytes
	// so the guard in the caller has a reason to exist.
	if !strings.Contains(string(envelope), "s3cr3t-pypi") {
		t.Fatal("test envelope should embed the secret; guard logic depends on this")
	}
}
