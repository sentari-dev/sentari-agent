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
	CurrentVersion      string
	LatestVersion       string
	MinSupportedVersion string
	UpgradeAvailable    bool
	Platform            PlatformManifest
	PlatformKey         string
	// ServedAt is the manifest's served_at timestamp (RFC 3339).
	// Carried into Apply so the freshness/replay high-water mark can be
	// enforced and persisted.
	ServedAt string
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
	// StateDir is where the last-applied high-water mark (version +
	// served_at) is persisted for replay/freshness enforcement.
	// Normally the agent data dir.  When empty, the freshness check is
	// skipped — acceptable for ad-hoc CLI use but the apply path warns.
	StateDir string
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
	// An upgrade is only available when the (signed, parse-validated)
	// latest_version is STRICTLY greater than the current version.  A
	// plain string-inequality test would accept a validly-signed OLDER
	// release, enabling a downgrade to a known-CVE build.
	upgrade := false
	if c.CurrentVer != "" {
		cmp, err := compareVersions(manifest.LatestVersion, c.CurrentVer)
		if err != nil {
			return nil, fmt.Errorf("compare current version: %w", err)
		}
		upgrade = cmp > 0
	}
	return &Plan{
		CurrentVersion:      c.CurrentVer,
		LatestVersion:       manifest.LatestVersion,
		MinSupportedVersion: manifest.MinSupportedVersion,
		UpgradeAvailable:    upgrade,
		Platform:            platform,
		PlatformKey:         platformKey,
		ServedAt:            manifest.ServedAt,
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

	// Re-canonicalize so Go's json.Marshal emits sorted keys, matching
	// the server-side signing.canonical_json byte-for-byte.  Crucially
	// this decodes numbers with json.Number (UseNumber) so integer
	// fields like size_bytes round-trip as their exact textual form —
	// a plain map[string]interface{} would coerce every number to
	// float64 and mangle integers >= 2^53, breaking ed25519.Verify on
	// an otherwise valid manifest.
	canonical, err := canonicalizePayload(env.Payload)
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
	// Reject a manifest whose version fields cannot be parsed as a
	// semver triple — a malformed or malicious manifest must never be
	// accepted on faith.  latest_version is mandatory;
	// min_supported_version is validated only when present.
	if _, err := parseSemver(m.LatestVersion); err != nil {
		return nil, fmt.Errorf("envelope: unparseable latest_version: %w", err)
	}
	if m.MinSupportedVersion != "" {
		if _, err := parseSemver(m.MinSupportedVersion); err != nil {
			return nil, fmt.Errorf("envelope: unparseable min_supported_version: %w", err)
		}
		// A manifest claiming a latest_version older than its own
		// min_supported_version is internally inconsistent — refuse it
		// rather than reason about a nonsensical floor.
		cmp, err := compareVersions(m.LatestVersion, m.MinSupportedVersion)
		if err != nil {
			return nil, fmt.Errorf("envelope: compare versions: %w", err)
		}
		if cmp < 0 {
			return nil, fmt.Errorf("envelope: latest_version %s is below min_supported_version %s", m.LatestVersion, m.MinSupportedVersion)
		}
	}
	return &m, nil
}

// canonicalizePayload re-serializes a raw signed payload into its
// canonical form (sorted keys, no insignificant whitespace, no HTML
// escaping, no trailing newline) WITHOUT losing integer precision.
//
// It decodes with json.Decoder + UseNumber so every JSON number is
// held as a json.Number (its exact source text) rather than a float64.
// json.Marshal then emits json.Number values verbatim, so an integer
// such as size_bytes=9007199254740993 (> 2^53) round-trips byte-for-
// byte instead of being coerced to a float and re-rendered with lost
// precision or an exponent.  This keeps the agent's canonical bytes
// identical to the Python server's signing.canonical_json output.
func canonicalizePayload(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("payload not valid JSON: %w", err)
	}
	if _, ok := v.(map[string]interface{}); !ok {
		return nil, errors.New("payload not a JSON object")
	}
	return canonicalJSON(v)
}

// canonicalJSON mirrors scanner.canonicalJSON: sorted keys via
// map[string]interface{} + json.Marshal, no whitespace, no HTML
// escaping, no trailing newline.  Duplicated here so the update
// package stays small and self-contained.  Callers that pass decoded
// values must use json.Number (not float64) for any large integers —
// see canonicalizePayload.
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

	// Windows cannot replace a running executable in place, and the
	// service-restart path is unimplemented there.  Refuse cleanly
	// BEFORE any download/swap so the operator gets an actionable
	// message instead of a half-applied upgrade plus a bogus restart
	// failure.  GOOS comes from the Client so this is testable on any
	// host and stays consistent with the runtime check in main.
	if c.GOOS == "windows" {
		return errors.New("self-update is not supported on Windows; use the installer (install.ps1) to upgrade")
	}

	// Independent downgrade guard: Check already filters, but Apply
	// must not trust a plan that was constructed or mutated elsewhere.
	// Refuse to install a version that is not strictly newer than the
	// running one, and never go below the manifest's own floor.
	if c.CurrentVer != "" {
		cmp, err := compareVersions(plan.LatestVersion, c.CurrentVer)
		if err != nil {
			return fmt.Errorf("apply: compare versions: %w", err)
		}
		if cmp <= 0 {
			return fmt.Errorf("apply: refusing downgrade/no-op: target %s is not newer than current %s", plan.LatestVersion, c.CurrentVer)
		}
	}
	if plan.MinSupportedVersion != "" {
		cmp, err := compareVersions(plan.LatestVersion, plan.MinSupportedVersion)
		if err != nil {
			return fmt.Errorf("apply: compare min_supported: %w", err)
		}
		if cmp < 0 {
			return fmt.Errorf("apply: refusing downgrade below min_supported_version %s", plan.MinSupportedVersion)
		}
	}

	// Replay/freshness gate: a validly-signed but stale manifest (an
	// equal-or-older version, or an equal version with a non-advancing
	// served_at) must be refused before any filesystem mutation so a
	// captured manifest cannot be replayed to pin/downgrade the agent.
	if err := checkFreshness(c.StateDir, plan.LatestVersion, plan.ServedAt); err != nil {
		return err
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

	// Binary is confirmed in place — advance the high-water mark before
	// restarting so a crash during restart cannot let an older manifest
	// be replayed afterwards.  A write failure here is non-fatal to the
	// (already successful) swap but is surfaced so the operator knows
	// replay protection did not advance.
	if c.StateDir != "" {
		if err := writeHighWater(c.StateDir, highWater{Version: plan.LatestVersion, ServedAt: plan.ServedAt}); err != nil {
			return fmt.Errorf("binary replaced but failed to record update high-water mark: %w", err)
		}
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
// ``dst`` as ``dst.prev`` for rollback.
//
// ``src`` is typically staged under the agent data dir (e.g.
// /var/lib/...), which is frequently a *different* filesystem from the
// install path (e.g. /usr/local/bin).  A naive ``os.Rename(src, dst)``
// then fails with EXDEV — and, fatally, it fails AFTER dst has already
// been moved to dst.prev, leaving the install path empty.  To avoid
// this the new bytes are first landed into a temp file in the SAME
// directory as ``dst`` so the activation rename is always intra-
// filesystem.  The sequence is:
//
//   1. Materialize src into ``<dir(dst)>/.<base(dst)>.new`` (rename if
//      same FS, else copy+fsync) — this is where EXDEV is absorbed,
//      BEFORE any destructive move.
//   2. If dst exists, rename dst → dst.prev (intra-FS, atomic).
//   3. Rename landing → dst (intra-FS, atomic).
//
// Because the only cross-FS step (1) happens before dst is touched, a
// failure there leaves the install path intact.
func atomicReplace(src, dst string) error {
	prev := dst + ".prev"
	landing := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".new")

	// Stat dst once so we can mirror its mode onto the landing file and
	// know whether a .prev needs preserving.
	var mode os.FileMode = 0o755
	dstExists := false
	if fi, err := os.Stat(dst); err == nil {
		dstExists = true
		mode = fi.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat install path: %w", err)
	}

	// Step 1: land the new bytes next to the install path.  Try an
	// intra-FS rename first; fall back to copy+fsync on EXDEV (or any
	// rename failure — copy is always safe, just slower).
	_ = os.Remove(landing)
	if err := os.Rename(src, landing); err != nil {
		if err := copyFileSync(src, landing, mode); err != nil {
			return fmt.Errorf("stage new binary into install dir: %w", err)
		}
		// Original staged file no longer needed once copied.
		_ = os.Remove(src)
	}
	if err := os.Chmod(landing, mode); err != nil {
		_ = os.Remove(landing)
		return fmt.Errorf("chmod landing binary: %w", err)
	}

	// Step 2: preserve the current binary as .prev (intra-FS).
	if dstExists {
		// Remove any stale .prev so the rename below cannot fail with
		// EEXIST on platforms where rename-onto-existing is not allowed.
		_ = os.Remove(prev)
		if err := os.Rename(dst, prev); err != nil {
			_ = os.Remove(landing)
			return fmt.Errorf("preserve previous binary: %w", err)
		}
	}

	// Step 3: activate (intra-FS rename — cannot EXDEV).
	if err := os.Rename(landing, dst); err != nil {
		// Best-effort restore so the install path is never left empty.
		if dstExists {
			_ = os.Rename(prev, dst)
		}
		_ = os.Remove(landing)
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// copyFileSync copies ``src`` to ``dst`` and fsyncs the destination
// before returning, so the bytes are durable on disk prior to the
// activation rename.  Used as the EXDEV fallback when src and dst live
// on different filesystems and os.Rename refuses to cross the boundary.
func copyFileSync(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create dest: %w", err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("copy bytes: %w", err)
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("fsync dest: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("close dest: %w", err)
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
