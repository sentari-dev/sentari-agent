//go:build enterprise

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/sentari-dev/sentari-agent/audit"
	"github.com/sentari-dev/sentari-agent/common/logging"
	"github.com/sentari-dev/sentari-agent/comms"
	"github.com/sentari-dev/sentari-agent/scanner"
)

// renewBeforeDays is how many days before the device cert's NotAfter the agent
// starts attempting renewal.  On the 365-day device cert this gives the agent
// roughly a month of (hourly) renewal attempts before expiry, enough to ride
// out a multi-week offline stretch yet short enough not to re-issue constantly.
const renewBeforeDays = 30

// renewClientConfig carries the mTLS-client material the serve loop needs to
// rebuild its client in-memory after a successful certificate renewal, so the
// next upload uses the new identity without a daemon restart.  It mirrors the
// comms.ClientConfig built at startup (main_enterprise.go ~line 418).
type renewClientConfig struct {
	serverURL string
	certFile  string
	keyFile   string
	caFile    string
	timeout   time.Duration
	proxy     comms.ProxyConfig
}

// certPaths returns the resolved cert material paths this config rebuilds from,
// so the renewal save/read can address the SAME files the client loads.
func (rc renewClientConfig) certPaths() comms.CertFilePaths {
	return comms.CertFilePaths{CertFile: rc.certFile, KeyFile: rc.keyFile, CAFile: rc.caFile}
}

// loadSigningTrustIntoKeyring reads the persisted license-map and install-gate
// signing-pubkey trust files from certDir and registers them with the scanner's
// in-memory keyring.  Run at startup and again after a successful cert renewal
// (which may re-save a rotated key) so a server signing-key rotation takes
// effect without a daemon restart.  Every failure is non-fatal and logged on
// stderr: a missing trust file just means that channel stays unverified, a
// corrupt one is surfaced loudly so an operator can re-register to reset it.
func loadSigningTrustIntoKeyring(certDir string) {
	if trust, err := comms.LoadLicenseMapTrust(certDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load license-map trust: %v\n", err)
	} else if trust != nil {
		if raw, err := base64.StdEncoding.DecodeString(trust.PubKeyB64); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: license-map pubkey is not valid base64: %v\n", err)
		} else if len(raw) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "Warning: license-map pubkey has wrong length (%d)\n", len(raw))
		} else {
			scanner.RegisterTrustedMapKey(trust.KeyID, ed25519.PublicKey(raw))
		}
	}

	if trust, err := comms.LoadInstallGateTrust(certDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not load install-gate trust: %v\n", err)
	} else if trust != nil {
		if raw, err := base64.StdEncoding.DecodeString(trust.PubKeyB64); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: install-gate pubkey is not valid base64: %v\n", err)
		} else if len(raw) != ed25519.PublicKeySize {
			fmt.Fprintf(os.Stderr, "Warning: install-gate pubkey has wrong length (%d)\n", len(raw))
		} else {
			scanner.RegisterTrustedInstallGateKey(trust.KeyID, ed25519.PublicKey(raw))
		}
	}
}

// registerAndSaveCerts runs the bootstrap enrollment against bootstrapClient
// and persists everything it returns: the device cert+key (atomically, to the
// resolved certPaths the mTLS client loads from), the server-assigned device id,
// and the license-map / install-gate / vuln-map signing-pubkey trust files.
// Trust persistence is best-effort (empty fields no-op on older servers); only a
// registration or cert-save failure is returned as fatal.  It is shared by the
// first-time startup registration path and the cert-expiry re-enrollment path
// (maybeReenrollOnExpiredCert) so both persist identical state.
func registerAndSaveCerts(ctx context.Context, bootstrapClient *comms.Client, hostname, enrollToken string, certPaths comms.CertFilePaths, certDir string, auditLog *audit.AuditLog) error {
	regLog := logging.LoggerFromContext(ctx)

	regLog.Info("registering agent", slog.String("hostname", hostname))
	regResp, deviceKeyPEM, err := bootstrapClient.RegisterWithToken(ctx, hostname, enrollToken)
	if err != nil {
		return fmt.Errorf("register with token: %w", err)
	}
	// Write to the resolved cert paths (config override or certDir fallback) so
	// the mTLS client finds them where it loads.
	if err := comms.SaveCertificatesAtomicAt(
		certPaths,
		[]byte(regResp.CACert),
		[]byte(regResp.DeviceCert),
		deviceKeyPEM,
	); err != nil {
		return fmt.Errorf("save certificates: %w", err)
	}
	if err := comms.SaveDeviceID(certDir, regResp.DeviceID); err != nil {
		regLog.Warn("persist device_id failed", slog.String("err", err.Error()))
	}
	// Persist the server's license-map signing pubkey so subsequent scan cycles
	// can verify signed /license-map envelopes without an operator-supplied pin.
	// Trust is anchored at the same TLS-fingerprint bootstrap the cert issuance
	// relies on.
	if err := comms.SaveLicenseMapTrust(
		certDir,
		regResp.LicenseMapKeyID,
		regResp.LicenseMapPubKey,
	); err != nil {
		regLog.Warn("persist license-map trust failed", slog.String("err", err.Error()))
	}
	// Same persistence story for the install-gate signing pubkey.  Empty fields
	// → SaveInstallGateTrust no-ops, the expected case on older servers.
	if err := comms.SaveInstallGateTrust(
		certDir,
		regResp.InstallGateKeyID,
		regResp.InstallGatePubKey,
	); err != nil {
		regLog.Warn("persist install-gate trust failed", slog.String("err", err.Error()))
	}
	// Same for the vuln-map (offline CVE channel) signing pubkey.  Empty strings
	// no-op so an upgrade-then-downgrade cycle doesn't blank a cached pubkey.
	if err := comms.SaveVulnMapTrust(
		certDir,
		regResp.VulnMapKeyID,
		regResp.VulnMapPubKey,
	); err != nil {
		regLog.Warn("persist vuln-map trust failed", slog.String("err", err.Error()))
	}
	logAudit(auditLog, "agent.registered", fmt.Sprintf("device_id=%s", regResp.DeviceID))
	regLog.Info("certificates saved", slog.String("cert_dir", certDir))
	return nil
}

// bootstrapParams carries what the cert-expiry re-enrollment path needs to
// rebuild a bootstrap client and re-register: the server URL, proxy, bootstrap
// CA trust, the enrollment token, and the resolved cert paths.  Passed to the
// serve loop so an expired device cert during an outage longer than the cert's
// remaining validity can trigger an automatic re-registration instead of a
// permanent TLS failure loop that needs manual cert deletion (finding
// offline-7).  An empty enrollToken means no token is configured — the loop then
// logs a loud "re-enrollment required" error instead of attempting auto-renewal.
type bootstrapParams struct {
	serverURL            string
	proxy                comms.ProxyConfig
	caCertFile           string
	bootstrapFingerprint string
	enrollToken          string
	certPaths            comms.CertFilePaths
	certDir              string
}

// certExpiryDecision is the outcome of decideCertExpiryAction: what the serve
// loop should do about the device cert's validity this cycle.
type certExpiryDecision int

const (
	// certOK: the cert is still valid — normal operation, no action.
	certOK certExpiryDecision = iota
	// certReenroll: the cert has expired AND an enrollment token is configured —
	// re-run the bootstrap registration to obtain a fresh identity.
	certReenroll
	// certExpiredNoToken: the cert has expired and NO token is configured — the
	// agent cannot self-heal; log a loud, actionable error instead of generic
	// TLS-handshake noise.
	certExpiredNoToken
)

// decideCertExpiryAction is the pure, testable core of the cert-expiry recovery
// policy.  It maps (cert NotAfter, now, whether a token is available) to the
// action the serve loop takes.  Renewal (maybeRenewCertificate) handles the
// pre-expiry window; this handles the case where renewal never succeeded and the
// cert has actually lapsed — e.g. an outage longer than the cert's remaining
// validity.
func decideCertExpiryAction(notAfter, now time.Time, haveToken bool) certExpiryDecision {
	if now.Before(notAfter) {
		return certOK
	}
	if haveToken {
		return certReenroll
	}
	return certExpiredNoToken
}

// maybeReenrollOnExpiredCert checks the device cert's validity and, when it has
// EXPIRED, either re-runs the bootstrap registration (when an enrollment token
// is configured) or logs a single loud "re-enrollment required" error.  It
// returns a rebuilt mTLS client when a re-enrollment succeeded, else the
// unchanged client.  Non-fatal: any failure keeps the current client and
// retries on the next cycle.  Called once at startup and once per serve cycle
// (after the pre-expiry renewal attempt), so the no-token error surfaces at most
// once per interval rather than as a per-request TLS flood.
func maybeReenrollOnExpiredCert(ctx context.Context, client *comms.Client, bp bootstrapParams, renewCfg renewClientConfig, hostname string, auditLog *audit.AuditLog) *comms.Client {
	log := logging.LoggerFromContext(ctx)

	notAfter, err := comms.DeviceCertNotAfterAt(bp.certPaths.CertFile)
	if err != nil {
		// Can't read the cert (not yet registered, or unreadable) — the register
		// path owns first issuance; nothing to re-enroll this cycle.
		return client
	}

	switch decideCertExpiryAction(notAfter, time.Now(), bp.enrollToken != "") {
	case certOK:
		return client
	case certExpiredNoToken:
		log.Error("device certificate has EXPIRED and no enrollment token is configured; "+
			"re-enrollment required — restart with --enroll-token / --enroll-token-file, or delete the "+
			"device certs to force a fresh bootstrap",
			slog.Time("not_after", notAfter))
		logAudit(auditLog, "cert.expired_no_token",
			fmt.Sprintf("not_after=%s", notAfter.UTC().Format(time.RFC3339)))
		return client
	case certReenroll:
		log.Warn("device certificate has EXPIRED; attempting automatic re-enrollment via bootstrap token",
			slog.Time("not_after", notAfter))
		newClient, err := reenrollWithToken(ctx, bp, renewCfg, hostname, auditLog)
		if err != nil {
			log.Warn("automatic re-enrollment failed; keeping expired cert and retrying next cycle",
				slog.String("err", err.Error()))
			return client
		}
		log.Info("device certificate re-enrolled after expiry")
		logAudit(auditLog, "agent.reenrolled", "reason=cert-expired")
		return newClient
	}
	return client
}

// reenrollWithToken builds a fresh no-cert bootstrap client (same trust
// precedence as first-time registration), re-registers to obtain and persist a
// new cert+key, and rebuilds the mTLS client from the freshly-saved material.
// Returns the new client on success.  On any failure the caller keeps the
// current (expired) client and retries next cycle.
func reenrollWithToken(ctx context.Context, bp bootstrapParams, renewCfg renewClientConfig, hostname string, auditLog *audit.AuditLog) (*comms.Client, error) {
	bootstrapClient, err := comms.NewClient(comms.ClientConfig{
		ServerURL:            bp.serverURL,
		Timeout:              30 * time.Second,
		Proxy:                bp.proxy,
		CACertFile:           bp.caCertFile,
		BootstrapFingerprint: bp.bootstrapFingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("build bootstrap client: %w", err)
	}
	if err := registerAndSaveCerts(ctx, bootstrapClient, hostname, bp.enrollToken, bp.certPaths, bp.certDir, auditLog); err != nil {
		return nil, err
	}
	// Re-load the (possibly rotated) signing pubkeys the re-registration just
	// persisted so verification uses them without a restart.
	loadSigningTrustIntoKeyring(bp.certDir)
	newClient, err := comms.NewClient(comms.ClientConfig{
		ServerURL:  renewCfg.serverURL,
		CertFile:   renewCfg.certFile,
		KeyFile:    renewCfg.keyFile,
		CACertFile: renewCfg.caFile,
		Timeout:    renewCfg.timeout,
		Proxy:      renewCfg.proxy,
	})
	if err != nil {
		return nil, fmt.Errorf("rebuild mTLS client after re-enroll: %w", err)
	}
	return newClient, nil
}

// maybeRenewCertificate checks the local device cert's remaining validity and,
// if it is inside the renewal window, attempts a renewal over the current mTLS
// client.  On success it atomically swaps the on-disk cert+key, re-saves the
// (idempotent) signing-pubkey trust files, rebuilds the mTLS client from the
// new material, and returns the new client.  On any failure it logs a warning
// and returns the unchanged client — renewal is always non-fatal and never
// leaves a half-written cert (the swap is atomic).
//
// The check reads the LOCAL cert NotAfter (no server round-trip just to
// decide), so an outside-window call is cheap: one file parse and return.
func maybeRenewCertificate(ctx context.Context, client *comms.Client, rc renewClientConfig, certDir, hostname string, auditLog *audit.AuditLog) *comms.Client {
	log := logging.LoggerFromContext(ctx)

	notAfter, err := comms.DeviceCertNotAfterAt(rc.certPaths().CertFile)
	if err != nil {
		// Can't read the cert (not yet registered, or unreadable) — nothing
		// to renew this cycle; the register path owns first issuance.
		log.Warn("cert renewal: could not read device cert NotAfter; skipping",
			slog.String("err", err.Error()))
		return client
	}

	remaining := time.Until(notAfter)
	if remaining >= renewBeforeDays*24*time.Hour {
		return client // Outside the window — no-op.
	}

	log.Info("device certificate within renewal window; attempting renewal",
		slog.Duration("remaining", remaining))

	resp, keyPEM, err := client.RenewCertificate(ctx, hostname)
	if err != nil {
		// Non-fatal: keep the current cert+client and retry next cycle.  Covers
		// an old server (404), a transient outage, or an air-gap window lapse.
		log.Warn("certificate renewal failed; keeping current cert",
			slog.String("err", err.Error()))
		return client
	}

	if err := comms.SaveCertificatesAtomicAt(rc.certPaths(),
		[]byte(resp.CACert), []byte(resp.DeviceCert), keyPEM); err != nil {
		// Atomic saver guarantees the old pair is untouched on failure.
		log.Warn("certificate renewal: atomic save failed; keeping current cert",
			slog.String("err", err.Error()))
		return client
	}

	// Re-persist signing pubkeys so a device that lost a trust file recovers it
	// on renewal.  These no-op on empty fields, so an older server that omits
	// them never blanks an existing trust file.
	if err := comms.SaveLicenseMapTrust(certDir, resp.LicenseMapKeyID, resp.LicenseMapPubKey); err != nil {
		log.Warn("cert renewal: re-save license-map trust failed", slog.String("err", err.Error()))
	}
	if err := comms.SaveInstallGateTrust(certDir, resp.InstallGateKeyID, resp.InstallGatePubKey); err != nil {
		log.Warn("cert renewal: re-save install-gate trust failed", slog.String("err", err.Error()))
	}
	if err := comms.SaveVulnMapTrust(certDir, resp.VulnMapKeyID, resp.VulnMapPubKey); err != nil {
		log.Warn("cert renewal: re-save vuln-map trust failed", slog.String("err", err.Error()))
	}

	// Re-load the (possibly rotated) signing pubkeys into the running scanner
	// keyring so a server-side signing-key rotation takes effect this cycle
	// rather than waiting for a daemon restart.  Mirrors the startup load;
	// non-fatal — a stale key just keeps verifying until the disk trust file
	// and keyring next agree.
	loadSigningTrustIntoKeyring(certDir)

	// Rebuild the mTLS client from the freshly-saved material so the next
	// upload authenticates with the new identity.  On rebuild failure, keep the
	// old client — the new cert is on disk and will be picked up on restart,
	// and the old fingerprint is still server-side valid during the overlap.
	newClient, err := comms.NewClient(comms.ClientConfig{
		ServerURL:  rc.serverURL,
		CertFile:   rc.certFile,
		KeyFile:    rc.keyFile,
		CACertFile: rc.caFile,
		Timeout:    rc.timeout,
		Proxy:      rc.proxy,
	})
	if err != nil {
		log.Warn("cert renewal: saved new cert but failed to rebuild mTLS client; will apply on next restart",
			slog.String("err", err.Error()))
		return client
	}

	log.Info("device certificate renewed",
		slog.Time("new_not_after", notAfterOrZero(rc.certPaths().CertFile)))
	logAudit(auditLog, "cert.renewed", fmt.Sprintf("device_id=%s", resp.DeviceID))
	return newClient
}

// notAfterOrZero reads the (now-renewed) device cert NotAfter at the explicit
// cert path for logging, returning the zero time if it can't be re-read.
// Best-effort observability only — never affects control flow.
func notAfterOrZero(certFile string) time.Time {
	if t, err := comms.DeviceCertNotAfterAt(certFile); err == nil {
		return t
	}
	return time.Time{}
}
