// Package update implements agent self-upgrade against the server's
// signed release manifest endpoint.
//
// The flow is deliberately split into three commands so a fleet
// operator can stage upgrades safely:
//
//   1. Check  — fetch /api/v1/agent/release/manifest, verify the
//      signed envelope against the install-gate pubkey pinned at
//      registration time, compare versions, return a Plan struct.
//      No filesystem mutation.
//
//   2. Apply  — download the per-platform binary from the URL in the
//      verified manifest, verify the SHA256 from the manifest matches
//      the downloaded bytes, write into a "staged" file, then move-
//      rename onto the install path while keeping the previous binary
//      as .prev for rollback.  Triggers a service restart via the
//      platform's service manager.
//
//   3. Rollback — swap .prev back into place and restart.  Used when
//      the upgraded agent fails health checks post-restart.
//
// Trust model:
//
//   * The install-gate ed25519 pubkey was learned at /register time
//     and persisted in the cert dir; this package re-uses that pin —
//     no new trust anchor is introduced.
//   * The downloaded binary is verified against a SHA256 contained
//     inside the signed envelope.  A compromised release directory
//     therefore cannot serve a forged binary that an enrolled agent
//     will trust.
//   * mTLS protects the wire path; only the holder of a valid agent
//     client certificate can ask for the manifest or binary.
package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// maxManifestBytes caps the manifest envelope to 1 MiB.  The
// server-side cap is 5 MiB; mirror with a tighter limit on the agent
// to slap an attacker who stuffs a manifest with millions of platform
// entries.  A real manifest is O(few KiB).
const maxManifestBytes = 1 * 1024 * 1024

// maxBinaryBytes caps a single downloaded binary.  Matches the
// server's hashing cap.
const maxBinaryBytes = 256 * 1024 * 1024

// envelope is the wire shape — payload kept as raw JSON so we can
// re-canonicalize it byte-for-byte and verify the signature without
// being affected by Go's map-iteration order.
type envelope struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
	KeyID     string          `json:"key_id"`
}

// Manifest is the verified release payload.
type Manifest struct {
	LatestVersion       string                      `json:"latest_version"`
	MinSupportedVersion string                      `json:"min_supported_version"`
	ReleasedAt          string                      `json:"released_at"`
	Notes               string                      `json:"notes"`
	Platforms           map[string]PlatformManifest `json:"platforms"`
	ServedAt            string                      `json:"served_at"`
}

// PlatformManifest is one platform entry inside the verified payload.
type PlatformManifest struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Filename  string `json:"filename"`
}

// Plan is the outcome of Check — what the agent learned from the
// manifest plus a recommendation.  Returned even when no upgrade is
// needed so a caller can print a stable status block in --check.
type Plan struct {
	CurrentVersion  string
	LatestVersion   string
	UpgradeAvailable bool
	Platform         PlatformManifest
	PlatformKey      string
}

// Client carries the HTTP client (mTLS already configured by the
// caller), the server base URL, and the trust anchor needed to
// verify the signed manifest envelope.
type Client struct {
	HTTPClient   *http.Client
	ServerURL    string
	TrustedKeys  map[string]ed25519.PublicKey
	CurrentVer   string
	GOOS         string
	GOARCH       string
}

// Check fetches and verifies the manifest, returning a Plan that the
// caller renders for --check or feeds into Apply.
func (c *Client) Check() (*Plan, error) {
	url := strings.TrimRight(c.ServerURL, "/") + "/api/v1/agent/release/manifest"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build manifest request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// "No upgrade available" is a normal, non-error state.
		return &Plan{
			CurrentVersion: c.CurrentVer,
			PlatformKey:    c.GOOS + "/" + c.GOARCH,
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest endpoint returned HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read manifest body: %w", err)
	}
	if int64(len(raw)) > maxManifestBytes {
		return nil, fmt.Errorf("manifest body exceeds %d bytes", maxManifestBytes)
	}

	manifest, err := verifyEnvelope(raw, c.TrustedKeys)
	if err != nil {
		return nil, err
	}

	platformKey := c.GOOS + "/" + c.GOARCH
	platform, ok := manifest.Platforms[platformKey]
	if !ok {
		// Server has a release but not for this platform — surface as
		// "no upgrade" rather than an error so the caller can print
		// the version difference and move on.
		return &Plan{
			CurrentVersion: c.CurrentVer,
			LatestVersion:  manifest.LatestVersion,
			PlatformKey:    platformKey,
		}, nil
	}
	return &Plan{
		CurrentVersion:   c.CurrentVer,
		LatestVersion:    manifest.LatestVersion,
		UpgradeAvailable: manifest.LatestVersion != c.CurrentVer && c.CurrentVer != "",
		Platform:         platform,
		PlatformKey:      platformKey,
	}, nil
}

// verifyEnvelope checks the signature against ``trusted`` and returns
// the decoded Manifest.  Re-canonicalizes the payload exactly the way
// the server signs it so the signature math agrees.
func verifyEnvelope(raw []byte, trusted map[string]ed25519.PublicKey) (*Manifest, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("envelope: malformed JSON: %w", err)
	}
	if len(env.Payload) == 0 || env.Signature == "" || env.KeyID == "" {
		return nil, errors.New("envelope: missing required field")
	}
	pub, ok := trusted[env.KeyID]
	if !ok {
		return nil, fmt.Errorf("envelope: unknown signing key_id %q", env.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return nil, fmt.Errorf("envelope: signature not base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("envelope: signature wrong length (%d)", len(sig))
	}

	// Re-canonicalize: round-trip through map[string]interface{} so
	// Go's json.Marshal emits sorted keys.  Matches the server-side
	// signing.canonical_json byte-for-byte for JSON containing only
	// strings, numbers, and nested maps/lists of those.
	var asMap map[string]interface{}
	if err := json.Unmarshal(env.Payload, &asMap); err != nil {
		return nil, fmt.Errorf("envelope: payload not a JSON object: %w", err)
	}
	canonical, err := canonicalJSON(asMap)
	if err != nil {
		return nil, fmt.Errorf("envelope: canonicalize: %w", err)
	}
	if !ed25519.Verify(pub, canonical, sig) {
		return nil, errors.New("envelope: signature verification failed")
	}

	var m Manifest
	if err := json.Unmarshal(env.Payload, &m); err != nil {
		return nil, fmt.Errorf("envelope: payload schema: %w", err)
	}
	if m.LatestVersion == "" {
		return nil, errors.New("envelope: payload missing latest_version")
	}
	return &m, nil
}

// canonicalJSON mirrors scanner.canonicalJSON: sorted keys via
// map[string]interface{} + json.Marshal, no whitespace, no HTML
// escaping, no trailing newline.  Duplicated here so the update
// package stays small and self-contained.
func canonicalJSON(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// Apply downloads the binary referenced by ``plan``, verifies its
// SHA256 against the manifest, atomically replaces ``installPath``,
// preserves the previous binary as ``installPath + ".prev"``, and
// triggers a service restart.  Returns an error before any
// filesystem mutation if the download / verification step fails.
//
// stagedDir is where the new binary lands before activation; any
// directory the agent can write to is fine.
func (c *Client) Apply(plan *Plan, installPath, stagedDir string) error {
	if plan == nil || !plan.UpgradeAvailable {
		return errors.New("apply called with no upgrade available")
	}
	if plan.Platform.URL == "" || plan.Platform.SHA256 == "" {
		return errors.New("apply called with empty platform manifest")
	}

	if err := os.MkdirAll(stagedDir, 0o755); err != nil {
		return fmt.Errorf("create staged dir: %w", err)
	}
	stagedPath := filepath.Join(stagedDir, "sentari-agent."+plan.LatestVersion+".new")

	if err := c.downloadAndVerify(plan, stagedPath); err != nil {
		return err
	}
	if err := os.Chmod(stagedPath, 0o755); err != nil {
		return fmt.Errorf("chmod staged binary: %w", err)
	}
	if err := atomicReplace(stagedPath, installPath); err != nil {
		return err
	}
	if err := restartService(installPath); err != nil {
		// Surface as a warning — the binary is already swapped; the
		// service manager may pick up the new binary on its own
		// schedule.  Returning nil here would hide a real problem,
		// returning the error wraps it so callers see what happened.
		return fmt.Errorf("binary replaced but service restart failed: %w", err)
	}
	return nil
}

// downloadAndVerify streams the binary from the URL in the manifest
// and writes it to ``dest`` only if the SHA256 matches.  Uses a
// scratch file alongside ``dest`` so a partial download cannot
// pretend to be a complete one if the process is killed mid-write.
func (c *Client) downloadAndVerify(plan *Plan, dest string) error {
	url := strings.TrimRight(c.ServerURL, "/") + plan.Platform.URL
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build binary request: %w", err)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("binary endpoint returned HTTP %d", resp.StatusCode)
	}

	scratch := dest + ".part"
	f, err := os.OpenFile(scratch, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open scratch file: %w", err)
	}
	hash := sha256.New()
	multi := io.MultiWriter(f, hash)
	written, err := io.Copy(multi, io.LimitReader(resp.Body, maxBinaryBytes+1))
	closeErr := f.Close()
	if err != nil {
		os.Remove(scratch)
		return fmt.Errorf("download binary: %w", err)
	}
	if closeErr != nil {
		os.Remove(scratch)
		return fmt.Errorf("close scratch file: %w", closeErr)
	}
	if written > maxBinaryBytes {
		os.Remove(scratch)
		return fmt.Errorf("binary exceeds %d bytes", maxBinaryBytes)
	}

	got := hex.EncodeToString(hash.Sum(nil))
	if got != plan.Platform.SHA256 {
		os.Remove(scratch)
		return fmt.Errorf("sha256 mismatch: manifest=%s downloaded=%s", plan.Platform.SHA256, got)
	}

	if err := os.Rename(scratch, dest); err != nil {
		os.Remove(scratch)
		return fmt.Errorf("rename scratch to dest: %w", err)
	}
	return nil
}

// atomicReplace moves ``src`` onto ``dst`` while keeping the previous
// ``dst`` as ``dst.prev`` for rollback.  The sequence is:
//
//   1. If dst exists, rename dst → dst.prev (atomic on POSIX).
//   2. Rename src → dst (atomic on POSIX).
//
// If step 2 fails after step 1 succeeded, the install path is empty
// and the binary lives at dst.prev — rollback restores it.
func atomicReplace(src, dst string) error {
	prev := dst + ".prev"
	if _, err := os.Stat(dst); err == nil {
		// Remove any stale .prev so the rename below cannot fail with
		// EEXIST on platforms where rename-onto-existing is not allowed.
		_ = os.Remove(prev)
		if err := os.Rename(dst, prev); err != nil {
			return fmt.Errorf("preserve previous binary: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat install path: %w", err)
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// Rollback swaps installPath with its .prev sibling and triggers a
// service restart.  Idempotent: when .prev is missing, returns a
// dedicated error so the caller can report "nothing to roll back to".
func Rollback(installPath string) error {
	prev := installPath + ".prev"
	if _, err := os.Stat(prev); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("no previous binary to roll back to")
		}
		return fmt.Errorf("stat previous binary: %w", err)
	}
	// Swap via a temp name so neither side is missing mid-swap.
	tmp := installPath + ".swapping"
	_ = os.Remove(tmp)
	if err := os.Rename(installPath, tmp); err != nil {
		return fmt.Errorf("move current aside: %w", err)
	}
	if err := os.Rename(prev, installPath); err != nil {
		// Best-effort restore so the install path is never empty.
		_ = os.Rename(tmp, installPath)
		return fmt.Errorf("promote previous binary: %w", err)
	}
	if err := os.Rename(tmp, prev); err != nil {
		// New .prev couldn't be created — non-fatal; the install
		// itself is fine.  Surface as warning via the error.
		return fmt.Errorf("rolled back, but could not move old binary to .prev: %w", err)
	}
	return restartService(installPath)
}
