//go:build enterprise

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/config"
	"github.com/sentari-dev/sentari-agent/scanner"
)

// signLicenseEnvelope builds a signed license-map envelope the agent will
// accept: it pins an ephemeral key under keyID and signs the canonical form of
// the payload (sorted keys, HTML escaping off, no trailing newline) so
// scanner.VerifyMapEnvelope's re-canonicalize-then-verify step succeeds.
// Ported from comms/poll_license_map_test.go's signMapEnvelope so runUpload can
// be driven end-to-end against a real *comms.Client + httptest server.
func signLicenseEnvelope(t *testing.T, keyID string, version int) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	scanner.RegisterTrustedMapKey(keyID, pub)

	payload := map[string]any{
		"version":  version,
		"spdx_map": map[string]string{"MIT License": "MIT"},
		"tier_map": map[string]string{"MIT": "permissive"},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	canonical := bytes.TrimRight(buf.Bytes(), "\n")
	sig := ed25519.Sign(priv, canonical)

	env, err := json.Marshal(map[string]any{
		"payload":   payload,
		"signature": base64.StdEncoding.EncodeToString(sig),
		"key_id":    keyID,
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return env
}

// hermeticHome redirects every host-config lookup installgate performs
// (os.UserHomeDir → HOME/USERPROFILE, plus APPDATA/LOCALAPPDATA/XDG_CONFIG_HOME)
// at a throwaway temp dir.  runUpload always runs the install-gate branch — with
// InstallGate disabled it calls installgate.RemoveAll, which only deletes
// Sentari-managed files but still resolves real host paths.  Pinning them at an
// empty temp dir keeps the test hermetic and cross-platform (never touches the
// developer's real pip.conf/.npmrc/etc.) and guarantees the teardown is a no-op.
func hermeticHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
}

// baseAgentCfg returns an AgentConfig whose scanner points at an empty temp dir
// (fast, zero-package scan) with install-gate disabled.
func baseAgentCfg(scanRoot string) config.AgentConfig {
	var cfg config.AgentConfig
	cfg.Scanner.ScanRoot = scanRoot
	cfg.Scanner.MaxDepth = 2
	cfg.Scanner.Interval = 3600
	cfg.InstallGate.Enabled = false
	return cfg
}

// auditEventTypes returns the set of event_type values currently in the audit
// log (best-effort; fails the test on a read error).
func auditEventTypes(t *testing.T, a *audit.AuditLog) map[string]string {
	t.Helper()
	entries, err := a.UnshippedEntries(0)
	if err != nil {
		t.Fatalf("UnshippedEntries: %v", err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		out[e["event_type"]] = e["detail"]
	}
	return out
}

// waitForAuditEvent polls the audit log until an entry of eventType appears or
// the deadline elapses, returning its detail. Used to synchronise a serveLoop
// cycle deterministically (e.g. wait for config.updated) before cancelling.
func waitForAuditEvent(t *testing.T, a *audit.AuditLog, eventType string, timeout time.Duration) (string, bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if detail, ok := auditEventTypes(t, a)[eventType]; ok {
			return detail, true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return "", false
}

// --- runUpload (upload_drain.go) --------------------------------------------

// TestRunUpload_GoodLicenseAppliesOverlayAndUploadsFresh drives runUpload end to
// end on the happy path: a valid signed license envelope is fetched + verified,
// the overlay is applied to the global map, the verified envelope is cached to
// disk for offline re-verification, the (empty-backlog) fresh scan is uploaded
// directly, and the local audit chain is re-anchored to the server.
func TestRunUpload_GoodLicenseAppliesOverlayAndUploadsFresh(t *testing.T) {
	hermeticHome(t)
	t.Cleanup(scanner.ResetToDefaults) // ApplyOverlay mutates global map state.

	dataDir := t.TempDir()
	certDir := t.TempDir()
	scanRoot := t.TempDir()
	// Persist a device_id so runUpload stamps result.DeviceID and shipAuditLog
	// actually ships (deviceID=="" is an early no-op).
	if err := os.WriteFile(filepath.Join(certDir, "device_id"), []byte("dev-runupload-1\n"), 0o600); err != nil {
		t.Fatalf("write device_id: %v", err)
	}

	newVersion := scanner.MapVersion() + 1000
	env := signLicenseEnvelope(t, "runupload-good", newVersion)

	var scanHits, shipHits int32
	var mu sync.Mutex
	shippedEvents := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/license-map":
			_, _ = w.Write(env)
		case "/api/v1/agent/scan":
			atomic.AddInt32(&scanHits, 1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		case "/api/v1/agent/audit-log":
			atomic.AddInt32(&shipHits, 1)
			// Capture the re-anchored entries' event types: on this happy path
			// they are marked shipped, so reading UnshippedEntries afterwards
			// would show nothing — the shipped batch is the authoritative record
			// that runUpload logged + re-anchored them.
			var req struct {
				Entries []struct {
					EventType string `json:"event_type"`
				} `json:"entries"`
			}
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &req)
			mu.Lock()
			for _, e := range req.Entries {
				shippedEvents[e.EventType] = true
			}
			mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetRetryConfig(comms.RetryConfig{MaxAttempts: 1})

	c, a := openTestCacheAudit(t)
	cp := cycleParams{hostname: "test-host", certDir: certDir, dataDir: dataDir}

	if err := runUpload(context.Background(), client, a, c, baseAgentCfg(scanRoot), cp, nil); err != nil {
		t.Fatalf("runUpload: %v", err)
	}

	// Verified overlay applied to the global map.
	if got := scanner.MapVersion(); got != newVersion {
		t.Fatalf("MapVersion = %d, want %d (verified overlay must be applied)", got, newVersion)
	}
	// Verified envelope cached for offline re-verification.
	if _, err := os.Stat(filepath.Join(dataDir, "license_map.json")); err != nil {
		t.Fatalf("verified license envelope not cached: %v", err)
	}
	// Fresh scan uploaded directly (empty backlog) + audit re-anchored.
	if atomic.LoadInt32(&scanHits) < 1 {
		t.Fatalf("scan endpoint hits = %d, want >=1", scanHits)
	}
	if atomic.LoadInt32(&shipHits) < 1 {
		t.Fatalf("audit-log ship hits = %d, want >=1 (device_id set)", shipHits)
	}
	mu.Lock()
	sawUpload := shippedEvents["upload.success"]
	mu.Unlock()
	if !sawUpload {
		t.Fatalf("re-anchored audit batch missing upload.success; got %v", shippedEvents)
	}
}

// TestRunUpload_BrokenLicenseEnvelopeIgnoredGracefully proves an unverifiable
// license envelope is handled gracefully: the overlay is NOT applied, no
// envelope is cached, no crash occurs, and the cycle still scans + uploads (the
// documented "keep serving the previously-cached overlay" behaviour).
func TestRunUpload_BrokenLicenseEnvelopeIgnoredGracefully(t *testing.T) {
	hermeticHome(t)
	t.Cleanup(scanner.ResetToDefaults)

	dataDir := t.TempDir()
	certDir := t.TempDir()
	scanRoot := t.TempDir()

	before := scanner.MapVersion()

	var scanHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/license-map":
			// Well-formed JSON, signed by no pinned key → verify fails.
			_, _ = w.Write([]byte(`{"payload":{"version":999999,"spdx_map":{"MIT License":"MIT"},"tier_map":{"MIT":"permissive"}},"signature":"AAAA","key_id":"nope"}`))
		case "/api/v1/agent/scan":
			atomic.AddInt32(&scanHits, 1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetRetryConfig(comms.RetryConfig{MaxAttempts: 1})

	c, a := openTestCacheAudit(t)
	cp := cycleParams{hostname: "test-host", certDir: certDir, dataDir: dataDir}

	if err := runUpload(context.Background(), client, a, c, baseAgentCfg(scanRoot), cp, nil); err != nil {
		t.Fatalf("runUpload returned error on a broken envelope (should degrade gracefully): %v", err)
	}

	// Overlay unchanged (unverified data must never be applied).
	if got := scanner.MapVersion(); got != before {
		t.Fatalf("MapVersion = %d, want unchanged %d (broken envelope must not apply)", got, before)
	}
	// No envelope cached on the failure path.
	if _, err := os.Stat(filepath.Join(dataDir, "license_map.json")); !os.IsNotExist(err) {
		t.Fatalf("license envelope must NOT be cached on verify failure (stat err=%v)", err)
	}
	// Cycle still scanned + uploaded despite the license refresh failing.
	if atomic.LoadInt32(&scanHits) < 1 {
		t.Fatalf("scan endpoint hits = %d, want >=1 (cycle must proceed)", scanHits)
	}
	if _, ok := auditEventTypes(t, a)["upload.success"]; !ok {
		t.Fatal("audit missing upload.success after a broken-envelope cycle")
	}
}

// TestRunUpload_DrainsBacklogFIFOThenUploadsFresh proves runUpload drains a
// pre-existing offline backlog strictly oldest-first and, only once the queue is
// empty, uploads the fresh scan LAST — so the server observes strict
// chronological order (finding offline-5), exercised through the full runUpload
// orchestration rather than drainCachedScans in isolation.
func TestRunUpload_DrainsBacklogFIFOThenUploadsFresh(t *testing.T) {
	hermeticHome(t)

	dataDir := t.TempDir()
	certDir := t.TempDir()
	scanRoot := t.TempDir()

	c, a := openTestCacheAudit(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i, host := range []string{"old-1", "old-2"} {
		if _, err := c.EnqueueScan(newTestScan(host, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("EnqueueScan %s: %v", host, err)
		}
	}

	var mu sync.Mutex
	var uploaded []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/license-map":
			// License refresh is incidental here; 500 exercises the
			// "refresh failed (using cached)" branch without aborting the cycle.
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/v1/agent/scan":
			var res scanner.ScanResult
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &res)
			mu.Lock()
			uploaded = append(uploaded, res.Hostname)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetRetryConfig(comms.RetryConfig{MaxAttempts: 1})

	cp := cycleParams{hostname: "test-host", certDir: certDir, dataDir: dataDir}
	if err := runUpload(context.Background(), client, a, c, baseAgentCfg(scanRoot), cp, nil); err != nil {
		t.Fatalf("runUpload: %v", err)
	}

	mu.Lock()
	got := append([]string(nil), uploaded...)
	mu.Unlock()

	if len(got) != 3 {
		t.Fatalf("server received %d uploads, want 3 (old-1, old-2, fresh); got %v", len(got), got)
	}
	if got[0] != "old-1" || got[1] != "old-2" {
		t.Fatalf("backlog not drained FIFO: got order %v, want [old-1 old-2 <fresh>]", got)
	}
	if got[2] == "old-1" || got[2] == "old-2" {
		t.Fatalf("fresh scan (%q) must be uploaded LAST, after the backlog", got[2])
	}

	events := auditEventTypes(t, a)
	if _, ok := events["cache.drain.success"]; !ok {
		t.Fatalf("audit missing cache.drain.success; got %v", keysOf(events))
	}
	if _, ok := events["upload.success"]; !ok {
		t.Fatalf("audit missing upload.success; got %v", keysOf(events))
	}
	// Queue fully drained.
	if n, err := c.PendingCount(); err != nil || n != 0 {
		t.Fatalf("pending after drain = %d (err %v), want 0", n, err)
	}
}

// TestRunUpload_EnqueuesFreshBehindBacklogWhenDrainStops proves the FIFO-safety
// branch: when a transient upload failure stops the drain with rows still
// queued, runUpload ENQUEUES the fresh scan behind the backlog instead of
// uploading it ahead of the older queued scans, and returns nil (the cycle is
// not an error — the backlog simply drains on a later cycle).
func TestRunUpload_EnqueuesFreshBehindBacklogWhenDrainStops(t *testing.T) {
	hermeticHome(t)

	dataDir := t.TempDir()
	certDir := t.TempDir()
	scanRoot := t.TempDir()

	c, a := openTestCacheAudit(t)
	base := time.Now().UTC().Add(-time.Hour)
	for i, host := range []string{"old-1", "old-2"} {
		if _, err := c.EnqueueScan(newTestScan(host, base.Add(time.Duration(i)*time.Minute))); err != nil {
			t.Fatalf("EnqueueScan %s: %v", host, err)
		}
	}

	var scanAttempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/license-map":
			w.WriteHeader(http.StatusInternalServerError)
		case "/api/v1/agent/scan":
			// Transient 503 on every upload — drain stops, backlog stays queued.
			atomic.AddInt32(&scanAttempts, 1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetRetryConfig(comms.RetryConfig{MaxAttempts: 1})

	cp := cycleParams{hostname: "test-host", certDir: certDir, dataDir: dataDir}
	// Backlog present + drain stops transiently ⇒ fresh scan is enqueued, not
	// uploaded; runUpload returns nil on this FIFO-preserving branch.
	if err := runUpload(context.Background(), client, a, c, baseAgentCfg(scanRoot), cp, nil); err != nil {
		t.Fatalf("runUpload should return nil when enqueuing behind a backlog, got: %v", err)
	}

	// old-1 + old-2 (undrained) + fresh (freshly enqueued) = 3 pending.
	n, err := c.PendingCount()
	if err != nil {
		t.Fatalf("PendingCount: %v", err)
	}
	if n != 3 {
		t.Fatalf("pending = %d, want 3 (old-1, old-2 undrained + fresh enqueued behind them)", n)
	}
	if _, ok := auditEventTypes(t, a)["scan.enqueued_behind_backlog"]; !ok {
		t.Fatal("audit missing scan.enqueued_behind_backlog (FIFO-safety branch not taken)")
	}
}

// --- serveLoop (serve_loop.go) ----------------------------------------------

// TestServeLoop_RunsCycleAppliesConfigAndShutsDownCleanly drives the OS-agnostic
// daemon body directly: it performs at least one full drain→scan→upload→renew→
// config-poll cycle, applies a server-pushed scan_interval (config.updated), then
// exits promptly when the root context is cancelled — writing the agent.shutdown
// audit entry stamped with the reason supplied by the shutdownReason stub. The
// renew/re-enroll steps are safe no-ops (no cert on disk).
func TestServeLoop_RunsCycleAppliesConfigAndShutsDownCleanly(t *testing.T) {
	hermeticHome(t)

	dataDir := t.TempDir()
	certDir := t.TempDir()
	scanRoot := t.TempDir()

	var scanHits, configHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/license-map":
			w.WriteHeader(http.StatusInternalServerError) // incidental
		case "/api/v1/agent/scan":
			atomic.AddInt32(&scanHits, 1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		case "/api/v1/agent/config":
			atomic.AddInt32(&configHits, 1)
			// Push a new interval so the config-poll step applies it and the
			// loop then parks in a long sleep, making the cancel path
			// deterministic.
			_, _ = w.Write([]byte(`{"scan_interval":3600}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := comms.NewClient(comms.ClientConfig{ServerURL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetRetryConfig(comms.RetryConfig{MaxAttempts: 1})

	c, a := openTestCacheAudit(t)

	// Short base interval so the first cycle starts immediately; the server's
	// 3600s push takes over for the (never-reached) second cycle's sleep.
	cfg := baseAgentCfg(scanRoot)
	cfg.Scanner.Interval = 1

	cp := cycleParams{hostname: "test-host", certDir: certDir, dataDir: dataDir}

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const wantReason = "SIGTERM-test"
	shutdownReason := func() string { return wantReason }

	done := make(chan struct{})
	go func() {
		serveLoop(rootCtx, shutdownReason, client, a, c, cfg, cp, renewClientConfig{}, bootstrapParams{})
		close(done)
	}()

	// Wait until a full cycle has demonstrably run (config-poll applied a new
	// interval → config.updated), then cancel so the loop takes its clean
	// shutdown path from the sleep.
	if _, ok := waitForAuditEvent(t, a, "config.updated", 10*time.Second); !ok {
		cancel()
		<-done
		t.Fatal("serveLoop never wrote config.updated — a full cycle did not complete")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serveLoop did not exit promptly after context cancel")
	}

	if atomic.LoadInt32(&scanHits) < 1 {
		t.Fatalf("scan hits = %d, want >=1 (at least one full cycle)", scanHits)
	}
	if atomic.LoadInt32(&configHits) < 1 {
		t.Fatalf("config-poll hits = %d, want >=1", configHits)
	}
	events := auditEventTypes(t, a)
	if _, ok := events["upload.success"]; !ok {
		t.Fatalf("audit missing upload.success (full runUpload cycle); got %v", keysOf(events))
	}
	shutdownDetail, ok := events["agent.shutdown"]
	if !ok {
		t.Fatalf("audit missing agent.shutdown; got %v", keysOf(events))
	}
	if shutdownDetail != "signal="+wantReason {
		t.Fatalf("agent.shutdown detail = %q, want %q", shutdownDetail, "signal="+wantReason)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
