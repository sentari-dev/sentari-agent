// Package comms provides the mTLS HTTPS client for agent-server communication.
// The agent uses a pull model: it initiates all connections outbound.
// No inbound ports are required on endpoints.
package comms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/common/logging"
	"github.com/sentari-dev/sentari-agent/common/secureperm"
	"github.com/sentari-dev/sentari-agent/scanner"
)

// maxResponseSize limits the amount of data the client will read from the
// server in a single response (10 MiB).  Prevents accidental/malicious
// memory exhaustion.
const maxResponseSize = 10 << 20 // 10 MiB

// maxErrorBodyLog is the maximum number of bytes from a server error response
// that will be included in error messages and log output.  Prevents leaking
// lengthy server internals (stack traces, internal IPs) to agent logs.
const maxErrorBodyLog = 512

// HTTPStatusError is returned by outbound operations (currently UploadScan)
// when the server answers with a non-success status that doRequest declined
// to retry — i.e. any 4xx except 429.  doRequest only retries transport
// errors, 429, and 5xx, so a 4xx reaches the caller intact; exposing the code
// as a typed error lets callers distinguish a PERMANENT client-side rejection
// (400 malformed, 413 payload-too-large) from a transient failure and decide
// whether to keep an item queued or mark it dead.  Retrieve with errors.As.
type HTTPStatusError struct {
	Op         string // operation label, e.g. "scan upload"
	StatusCode int    // the HTTP status code the server returned
	Body       string // truncated server error body, for diagnostics
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("%s failed (HTTP %d): %s", e.Op, e.StatusCode, e.Body)
}

// ClientConfig holds the mTLS client configuration.
type ClientConfig struct {
	ServerURL            string
	CertFile             string // Client certificate path
	KeyFile              string // Client private key path
	CACertFile           string // Server CA certificate path (for pinning)
	Timeout              time.Duration
	Proxy                ProxyConfig // Forward proxy settings (optional)
	BootstrapFingerprint string      // SHA-256 fingerprint of server TLS cert (hex, colon-separated) for bootstrap pinning
}

// ProxyConfig holds forward proxy settings for agent-to-server communication.
type ProxyConfig struct {
	HTTPSProxy   string // Proxy URL (e.g. http://proxy.corp:3128)
	NoProxy      string // Bypass list, comma-separated hostnames/IPs
	AuthUser     string // Proxy basic auth username
	AuthPassFile string // Path to file containing proxy password (trimmed)
}

// RegisterResponse is the server response to a registration request.
// The server issues a real mTLS device certificate on registration and
// piggybacks the license-map signing pubkey on the same response so the
// agent can verify signed /license-map envelopes without an operator-
// supplied pin.  Trust for both the cert and the pubkey rides on the
// same TLS fingerprint the agent pinned at bootstrap.
type RegisterResponse struct {
	DeviceID   string `json:"device_id"`
	CACert     string `json:"ca_cert"`     // PEM CA certificate — pin for subsequent connections
	DeviceCert string `json:"device_cert"` // PEM device certificate
	DeviceKey  string `json:"device_key"`  // Deprecated: unused since CSR-based registration; kept for backward compat.
	// License-map signing — base64-encoded raw 32-byte ed25519 pubkey
	// and the matching key_id the server will set on signed envelopes.
	// Empty when the server could not load/generate its signing key
	// (logged server-side; agent treats license-map as unavailable).
	LicenseMapPubKey string `json:"license_map_pubkey"`
	LicenseMapKeyID  string `json:"license_map_key_id"`
	// Install-gate (policy-map) signing — same shape and the same
	// trust-bootstrap story as the license-map fields above; separate
	// keypair on the server so rotation + compromise scope are
	// independent.  Empty when the server could not load/generate its
	// install-gate signing key — agent treats install-gate as
	// unavailable and writes no native package-manager configs rather
	// than trust unsigned policy.
	InstallGatePubKey string `json:"install_gate_pubkey"`
	InstallGateKeyID  string `json:"install_gate_key_id"`
	// Vuln-map (offline CVE channel) signing — same trust-bootstrap
	// story as the license-map and install-gate fields above; a third
	// independent keypair so a compromise of one channel never leaks
	// across the others.  Empty when the server has not provisioned a
	// vuln-map signing key (older deployments, or an air-gap operator
	// who has not yet imported the NVD bundle).  When present these are
	// persisted via SaveVulnMapTrust so a later vuln-map consumer can
	// verify signed envelopes; `omitempty` keeps the wire format
	// byte-identical for older servers that don't emit these fields at
	// all, so older agents round-trip the response unchanged.
	VulnMapPubKey string `json:"vuln_map_pubkey,omitempty"`
	VulnMapKeyID  string `json:"vuln_map_key_id,omitempty"`
	Message       string `json:"message"`
}

// AgentConfig is the configuration received from the server during polling.
type AgentConfig struct {
	ScanInterval int    `json:"scan_interval"` // Seconds between scans
	ScanRoot     string `json:"scan_root"`
	MaxDepth     int    `json:"max_depth"`
	Version      string `json:"config_version"`
}

// Client is the mTLS HTTP client for communicating with sentari-server.
type Client struct {
	serverURL  string
	httpClient *http.Client
	// systemTrustBootstrap records that the client was built with neither
	// a CA cert file nor a bootstrap fingerprint, so server verification
	// falls back to the OS trust store — a mechanism ADR 0004 rejects as
	// the sole bootstrap anchor.  RegisterWithToken logs a warning when
	// trust is anchored through such a client so the gap is observable.
	systemTrustBootstrap bool
	// retry, when non-nil, overrides the defaultRetryConfig used by
	// doRequest.  Tests set this to shrink waits; production leaves
	// it nil so the 5-attempt / 60 s-cap defaults apply.
	retry *RetryConfig
}

// SetRetryConfig installs a custom retry policy on the client.
// Intended for tests — production callers should stick with the
// defaults tuned for the hourly scan cadence.
func (c *Client) SetRetryConfig(cfg RetryConfig) {
	c.retry = &cfg
}

// HTTPClient returns the underlying *http.Client so consumers in
// other packages (e.g. scanner/update) can issue requests with the
// same mTLS/proxy/timeout configuration the agent uses everywhere
// else.  Intentionally read-only — callers must not mutate it.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// CloseIdleConnections closes any idle keep-alive connections held by this
// client's transport.  The caller that swaps in a new client on cert renewal /
// re-enroll should call this on the OLD client so its idle mTLS sockets are
// released at once rather than lingering until IdleConnTimeout.  Safe to call
// on a zero-request client and safe to call more than once.
func (c *Client) CloseIdleConnections() {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
}

// NewClient creates a new mTLS client. If cert/key files are not provided,
// it creates a plain TLS client (no client cert) for initial registration only.
// If ProxyConfig.HTTPSProxy is set, all requests are routed through the proxy.
// If HTTPSProxy is empty, the default Go behavior applies (respects HTTP_PROXY/
// HTTPS_PROXY environment variables).
func NewClient(cfg ClientConfig) (*Client, error) {
	// Refuse to build a cleartext client.  mTLS is a hard charter constraint:
	// every agent->server request carries the device inventory and (once
	// enrolled) the mTLS client certificate, so an http:// ServerURL would
	// silently ship that material in cleartext.  Validate the scheme up front
	// — the single construction chokepoint every caller (cmd, scanner/update)
	// funnels through — so a misconfiguration fails loudly at startup instead
	// of leaking on the wire.
	if err := validateServerURL(cfg.ServerURL); err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load client certificate for mTLS if provided.
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate for server verification (certificate pinning).
	// Loaded BEFORE the fingerprint block: per ADR 0004 the CA file is the
	// primary trust anchor and the fingerprint only stands alone when no
	// CA is configured.
	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("load CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Pin the server TLS certificate by SHA-256 fingerprint during bootstrap.
	// This prevents MITM attacks when the agent has not yet received the CA
	// certificate from the server.
	//
	// Trust precedence (ADR 0004):
	//   - CA configured + fingerprint: standard chain validation against the
	//     CA pool stays ON, and the pin runs as an ADDITIONAL check —
	//     crypto/tls invokes VerifyConnection only after normal verification
	//     succeeds when InsecureSkipVerify is false.
	//   - Fingerprint only: no CA to chain-walk against, so chain validation
	//     is disabled and the pin is the sole (manual) verification.
	if cfg.BootstrapFingerprint != "" {
		expected := strings.ToLower(strings.ReplaceAll(cfg.BootstrapFingerprint, ":", ""))
		if tlsConfig.RootCAs == nil {
			tlsConfig.InsecureSkipVerify = true // We verify manually via fingerprint.
		}
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("server presented no TLS certificate")
			}
			leaf := cs.PeerCertificates[0]
			h := sha256.Sum256(leaf.Raw)
			actual := hex.EncodeToString(h[:])
			if actual != expected {
				return fmt.Errorf("server TLS fingerprint mismatch: got %s, want %s", actual, expected)
			}
			return nil
		}
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Bound idle-connection lifetime.  The agent is a long-lived daemon
		// that replaces this whole client on every cert renewal / re-enroll
		// (a fresh mTLS identity means a fresh *http.Client).  Without an idle
		// timeout the kernel keeps the old transport's TCP connections open
		// until the server or a firewall reaps them, so idle sockets can pile
		// up across renewals.  IdleConnTimeout reaps them itself; the small
		// per-host cap matches the reality that the agent talks to exactly one
		// server.  Callers that drop a client should also call
		// CloseIdleConnections to release its sockets immediately.
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}

	// Configure forward proxy if specified.
	if cfg.Proxy.HTTPSProxy != "" {
		proxyFunc, err := buildProxyFunc(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("configure proxy: %w", err)
		}
		transport.Proxy = proxyFunc
	}

	return &Client{
		serverURL:            cfg.ServerURL,
		systemTrustBootstrap: cfg.CACertFile == "" && cfg.BootstrapFingerprint == "",
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// Never follow redirects.  A MITM or misconfigured server could
			// redirect scan uploads (with mTLS credentials) to a third party.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// validateServerURL enforces the mTLS charter at client construction: the
// server URL MUST be https.  A cleartext http:// URL is rejected because agent
// scan uploads and the mTLS client certificate would otherwise travel in the
// clear.  The sole exception is http:// to a loopback host, which never leaves
// the machine — the in-process httptest harness relies on this and it carries
// no on-the-wire exposure.  A missing or unrecognised scheme is a hard error so
// a bare "host:port" config can never degrade into a silent cleartext client.
func validateServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("server URL %q uses cleartext http to a non-loopback host; mTLS requires https://", raw)
	case "":
		return fmt.Errorf("server URL %q is missing a scheme; expected https://", raw)
	default:
		return fmt.Errorf("server URL %q uses unsupported scheme %q; expected https://", raw, u.Scheme)
	}
}

// isLoopbackHost reports whether host is "localhost" or a loopback IP literal
// (127.0.0.0/8, ::1).  Used to permit the http:// loopback carve-out in
// validateServerURL without opening a door to cleartext over a real network.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// buildProxyFunc creates an http.Transport.Proxy function from the ProxyConfig.
// It parses the proxy URL, injects auth credentials (AuthUser + AuthPassFile
// take precedence over credentials embedded in the URL), and respects the
// NoProxy bypass list.
func buildProxyFunc(pc ProxyConfig) (func(*http.Request) (*url.URL, error), error) {
	proxyURL, err := url.Parse(pc.HTTPSProxy)
	if err != nil {
		// url.Parse wraps the RAW url string — credentials and all — inside a
		// *url.Error whose Error() prints it verbatim, so we must never surface
		// that error with %w. Unwrap to the underlying reason (which carries the
		// bad token, never the userinfo) and pair it with a redacted URL so a
		// proxy URL like https://user:pass@proxy:8080 can't leak its password
		// into agent logs.
		reason := err
		var uerr *url.Error
		if errors.As(err, &uerr) {
			reason = uerr.Err
		}
		return nil, fmt.Errorf("parse proxy URL %q: %w", redactProxyURL(pc.HTTPSProxy), reason)
	}

	if proxyURL.Scheme == "" {
		return nil, fmt.Errorf("proxy URL %q missing scheme (expected http:// or https://)", redactProxyURL(pc.HTTPSProxy))
	}

	// Fail closed on a cleartext proxy that carries credentials.  An http://
	// proxy with basic auth makes Go send `Proxy-Authorization: Basic <base64>`
	// inside the CONNECT request over the CLEARTEXT agent<->proxy segment, so
	// any on-path attacker there captures the proxy credential.  Refuse at
	// construction (this is a compliance product) — the same chokepoint as the
	// validateServerURL cleartext check.  An http:// proxy WITHOUT auth stays
	// allowed (no credential to leak); an https:// proxy WITH auth stays allowed
	// (the credential rides inside TLS to the proxy).  Redact the URL so the
	// refusal itself can never surface an embedded credential.
	//
	// Credentials arrive by EITHER route: separate AuthUser/AuthPassFile config
	// OR userinfo embedded directly in the proxy URL (http://user:pass@proxy).
	// Go sends Proxy-Authorization from URL userinfo just the same, so the guard
	// must also refuse proxyURL.User != nil — otherwise a URL-embedded credential
	// with no separate auth config would slip past onto the cleartext segment.
	if proxyURL.Scheme == "http" && (pc.AuthUser != "" || pc.AuthPassFile != "" || proxyURL.User != nil) {
		return nil, fmt.Errorf(
			"refusing to send proxy credentials over a cleartext http:// proxy; use an https:// proxy or remove proxy auth (proxy %q)",
			redactProxyURL(pc.HTTPSProxy))
	}

	// Inject auth credentials from AuthUser + AuthPassFile.
	// This takes precedence over any user:pass embedded in the URL.
	if pc.AuthUser != "" {
		password, err := readProxyPassword(pc.AuthPassFile)
		if err != nil {
			return nil, fmt.Errorf("read proxy password: %w", err)
		}
		proxyURL.User = url.UserPassword(pc.AuthUser, password)
	}

	// Parse NoProxy bypass list into a set of trimmed, lowercased entries.
	bypassList := parseNoProxy(pc.NoProxy)

	return func(req *http.Request) (*url.URL, error) {
		if shouldBypass(req.URL.Hostname(), bypassList) {
			return nil, nil // Direct connection, no proxy.
		}
		return proxyURL, nil
	}, nil
}

// redactProxyURL returns a proxy URL string that is safe to embed in error and
// log messages: any embedded userinfo (user:password@) is masked so credentials
// never leak. A proxy URL is operator-supplied config that legitimately carries
// basic-auth credentials, and every error site that echoes it back must scrub
// them first.
//
// It is deliberately lenient: when the raw value parses as a URL, Go's
// url.URL.Redacted() masks the password (…:xxxxx@…); when it does NOT parse
// (the exact case the parse-error site handles), it falls back to masking any
// "user:password@" span manually so a parse failure can never be the thing that
// surfaces the credentials.
func redactProxyURL(raw string) string {
	if u, err := url.Parse(raw); err == nil {
		// Redacted() is a no-op when there is no userinfo, and masks only the
		// password when there is — matching the parse-succeeds error sites.
		return u.Redacted()
	}
	// Unparseable input: strip credentials by hand. Keep an optional
	// "scheme://" prefix, then if a "userinfo@" span is present, redact the
	// password portion (Go's Redacted() uses the literal "xxxxx").
	scheme := ""
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		scheme = rest[:i+3]
		rest = rest[i+3:]
	}
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return raw // no userinfo to redact
	}
	creds, host := rest[:at], rest[at:] // host retains the leading '@'
	if colon := strings.IndexByte(creds, ':'); colon >= 0 {
		creds = creds[:colon] + ":xxxxx"
	} else {
		// Bare "user@" with no password: still mask it defensively.
		creds = "xxxxx"
	}
	return scheme + creds + host
}

// readProxyPassword reads the proxy password from a file, trimming whitespace.
// Returns an empty string without error if the path is empty.
func readProxyPassword(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read proxy password file %q: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// parseNoProxy splits a comma-separated bypass list into trimmed, lowercased
// entries. Empty entries are skipped.
func parseNoProxy(noProxy string) []string {
	if noProxy == "" {
		return nil
	}
	parts := strings.Split(noProxy, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// shouldBypass returns true if the given host matches any entry in the bypass
// list. Matching rules:
//   - Exact match (case-insensitive)
//   - Suffix match: entry ".example.com" matches "foo.example.com"
//   - Wildcard "*" bypasses all hosts
func shouldBypass(host string, bypassList []string) bool {
	host = strings.ToLower(host)
	for _, entry := range bypassList {
		if entry == "*" {
			return true
		}
		if host == entry {
			return true
		}
		// Suffix match: ".example.com" matches "foo.example.com"
		if strings.HasPrefix(entry, ".") && strings.HasSuffix(host, entry) {
			return true
		}
		// Also match "example.com" against "sub.example.com" (common convention).
		if !strings.HasPrefix(entry, ".") && strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

// RegisterWithToken sends a registration request including an enrollment token.
// The agent generates its own ECDSA P-256 keypair and sends a CSR to the server.
// The server signs the CSR and returns the device certificate + CA certificate.
// The private key never leaves the agent.
//
// ctx carries the scan-cycle request_id so the registration log line on
// the server joins the agent's startup trace.  Retries on transient
// network / 429 / 5xx via doRequest with exponential backoff.
func (c *Client) RegisterWithToken(ctx context.Context, hostname, enrollmentToken string) (*RegisterResponse, []byte, error) {
	// Registration is the moment trust is anchored: the CA cert and signing
	// pubkeys returned here are pinned for every subsequent connection.
	// Doing that over a connection verified only by the OS trust store is
	// the silent-TOFU gap ADR 0004 warns about — make it loud.
	if c.systemTrustBootstrap {
		logging.LoggerFromContext(ctx).Warn(
			"bootstrap trust falling back to system trust store; configure ca_cert_file or --bootstrap-ca-fingerprint")
	}

	// Generate a fresh ECDSA P-256 keypair and CSR on the agent.  Shared
	// byte-for-byte with the renewal path via buildCSR.
	csrPEM, keyPEM, err := buildCSR(hostname)
	if err != nil {
		return nil, nil, err
	}

	payload := map[string]string{
		"hostname":         hostname,
		"enrollment_token": enrollmentToken,
		"os":               runtime.GOOS,
		"arch":             runtime.GOARCH,
		"agent_version":    scanner.Version,
		"machine_id":       scanner.GetDeviceID(),
		"csr":              string(csrPEM),
	}
	body, _ := json.Marshal(payload)

	// reqBuilder must produce a fresh Request on every attempt — the
	// retry path discards resp.Body but the next attempt still needs
	// its own body reader, so we re-wrap the same bytes.
	resp, err := c.doRequest(ctx, "agent_register", func(ctx context.Context) (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/v1/agent/register", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", "application/json")
		return r, nil
	})
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, nil, fmt.Errorf("registration failed (HTTP %d): %s", resp.StatusCode, truncateBytes(respBody, maxErrorBodyLog))
	}

	var regResp RegisterResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&regResp); err != nil {
		return nil, nil, fmt.Errorf("decode registration response: %w", err)
	}

	// Validate that the issued device cert actually chains to the CA the
	// server returned in the same bundle.  Trust for this bundle rides on
	// the TLS fingerprint pinned at bootstrap, but a buggy/compromised
	// server could still hand back an internally-inconsistent bundle; we
	// must not persist a device cert that won't verify against the CA we're
	// about to pin, or the agent bricks its own mTLS on the next cycle.
	if err := verifyDeviceCertChain([]byte(regResp.DeviceCert), []byte(regResp.CACert)); err != nil {
		return nil, nil, fmt.Errorf("registration bundle rejected: %w", err)
	}

	return &regResp, keyPEM, nil
}

// buildCSR generates a fresh ECDSA P-256 keypair and a CSR with the given
// hostname as CN, returning the PEM-encoded CSR and the PEM-encoded private
// key.  Both registration and renewal use this so the two paths emit a
// byte-identical CSR shape; the private key never leaves the agent.
func buildCSR(hostname string) (csrPEM, keyPEM []byte, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate device key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Sentari"},
			OrganizationalUnit: []string{"Device"},
			CommonName:         hostname,
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal device key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM, nil
}

// RenewCertificate requests a new device certificate over the agent's existing
// authenticated mTLS channel.  It is registration-minus-the-enrollment-token:
// a FRESH P-256 keypair + CSR (key rotation comes free with cert rotation) is
// POSTed to /api/v1/agent/renew; the current still-valid cert is the
// authentication, so there is no enrollment token in the body and the server
// derives identity from the presenting cert, ignoring any hostname here.
//
// On success it returns the re-issued bundle and the fresh private key (PEM);
// the caller atomically swaps both on disk (see SaveCertificatesAtomic) and
// rebuilds its mTLS client.  A non-2xx or network error returns an error and
// the caller keeps using the current cert — renewal is always non-fatal.
//
// The returned device cert is verified to chain to the returned CA before
// returning, mirroring the registration guard: a buggy/compromised server must
// not be able to make the agent persist a cert that won't verify against the
// CA it is about to pin.
func (c *Client) RenewCertificate(ctx context.Context, hostname string) (*RegisterResponse, []byte, error) {
	csrPEM, keyPEM, err := buildCSR(hostname)
	if err != nil {
		return nil, nil, err
	}

	payload := map[string]string{"csr": string(csrPEM)}
	body, _ := json.Marshal(payload)

	resp, err := c.doRequest(ctx, "agent_renew", func(ctx context.Context) (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/v1/agent/renew", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", "application/json")
		return r, nil
	})
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, nil, fmt.Errorf("renewal failed (HTTP %d): %s", resp.StatusCode, truncateBytes(respBody, maxErrorBodyLog))
	}

	var renewResp RegisterResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&renewResp); err != nil {
		return nil, nil, fmt.Errorf("decode renewal response: %w", err)
	}

	if err := verifyDeviceCertChain([]byte(renewResp.DeviceCert), []byte(renewResp.CACert)); err != nil {
		return nil, nil, fmt.Errorf("renewal bundle rejected: %w", err)
	}

	return &renewResp, keyPEM, nil
}

// verifyDeviceCertChain confirms the PEM device cert verifies against the PEM
// CA cert.  Returns an error describing the failure if the device cert does
// not chain to the CA (or either input is unparseable).
func verifyDeviceCertChain(deviceCertPEM, caCertPEM []byte) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCertPEM) {
		return fmt.Errorf("verify chain: CA cert is not valid PEM")
	}

	block, _ := pem.Decode(deviceCertPEM)
	if block == nil {
		return fmt.Errorf("verify chain: device cert is not valid PEM")
	}
	deviceCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("verify chain: parse device cert: %w", err)
	}

	// We only care that the leaf chains to the returned CA — not hostname
	// (this is a client cert) and not key-usage policy beyond what the CA
	// asserts.  Skip time validity is NOT requested; an expired leaf is a
	// real problem worth surfacing at registration.
	if _, err := deviceCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("verify chain: device cert does not chain to returned CA: %w", err)
	}
	return nil
}

// CertFilePaths is the explicit on-disk location of the three mTLS material
// files.  It exists because an operator can override any of them in config
// ([server] cert_file/key_file/ca_cert_file); when that happens the renewal
// save/read AND the registration existence check must operate on the SAME
// paths the mTLS client loads from — not a hardcoded <dir>/device.crt
// convention, which would silently rotate (or re-register against) the wrong
// files on custom-path deployments.
type CertFilePaths struct {
	CertFile string // device cert path (mTLS leaf)
	KeyFile  string // device private key path
	CAFile   string // server CA cert path (pin)
}

// SaveCertificatesAtomicAt is SaveCertificatesAtomic addressed by explicit file
// paths rather than a directory + fixed filenames.  Same crash-safe sequence
// (write-temp + fsync + rename, key renamed before cert), same file modes
// (cert/key 0600, ca 0640).  Each file's parent directory is created if needed
// so the three paths may live in different directories.
func SaveCertificatesAtomicAt(p CertFilePaths, caCert, deviceCert, deviceKey []byte) error {
	type certFile struct {
		path    string
		tmpPath string
		data    []byte
		mode    os.FileMode
	}
	// Order matters for the rename phase: key first, then cert.  ca is not
	// paired with the key so its ordering is irrelevant; keep it last.
	files := []certFile{
		{path: p.KeyFile, data: deviceKey, mode: 0600},
		{path: p.CertFile, data: deviceCert, mode: 0600},
		{path: p.CAFile, data: caCert, mode: 0640},
	}

	// Phase 1: write + fsync every temp file alongside its destination.  If
	// any write fails, unlink all temps and bail — the live files are
	// untouched.
	cleanup := func() {
		for i := range files {
			if files[i].tmpPath != "" {
				_ = os.Remove(files[i].tmpPath)
			}
		}
	}
	for i := range files {
		dir := filepath.Dir(files[i].path)
		if err := os.MkdirAll(dir, 0700); err != nil {
			cleanup()
			return fmt.Errorf("create dir for %s: %w", files[i].path, err)
		}
		// Restrict the parent directory before writing into it.  On Windows
		// this strips the inherited "Users" read grant and makes the ACE
		// inheritable so the cert/key files below land with restricted
		// permissions; on POSIX it re-asserts 0700.  Best-effort: the data
		// dir is also hardened at startup, so a miss here is not fatal.
		_ = secureperm.HardenDir(dir)
		tmp := files[i].path + ".tmp"
		files[i].tmpPath = tmp
		if err := writeAndSync(tmp, files[i].data, files[i].mode); err != nil {
			cleanup()
			return fmt.Errorf("write %s: %w", files[i].path, err)
		}
	}

	// Phase 2: rename each temp into place (atomic per-file).
	for i := range files {
		if err := os.Rename(files[i].tmpPath, files[i].path); err != nil {
			files[i].tmpPath = ""
			cleanup()
			return fmt.Errorf("rename %s: %w", files[i].path, err)
		}
		files[i].tmpPath = ""
		// Explicitly restrict the private key and cert bundle on the final
		// path too — defence in depth against a non-inheriting parent ACL.
		_ = secureperm.HardenFile(files[i].path)
	}

	return nil
}

// DeviceCertNotAfterAt parses the device cert at the explicit path and returns
// its NotAfter time.  Used by the serve loop to decide whether the cert is
// within the renewal window without a server round-trip; the explicit path lets
// it honour a config-overridden cert location.
func DeviceCertNotAfterAt(certFile string) (time.Time, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return time.Time{}, fmt.Errorf("read device cert: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return time.Time{}, fmt.Errorf("device cert is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse device cert: %w", err)
	}
	return cert.NotAfter, nil
}

// CertsExistAt returns true if all three explicit cert material files are
// present, honouring config-overridden cert paths.  Used by the registration
// gate so a custom-path deployment with valid certs does not spuriously
// re-register.
func CertsExistAt(p CertFilePaths) bool {
	for _, path := range []string{p.CAFile, p.CertFile, p.KeyFile} {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

// SaveCertificatesAtomic writes the CA cert, device cert, and device key to
// certDir under the conventional filenames (ca.crt / device.crt / device.key)
// using the same crash-safe write-temp + fsync + rename sequence as the
// production saver.  It is a thin convenience wrapper over
// SaveCertificatesAtomicAt: it maps certDir + fixed filenames onto explicit
// paths and delegates, so there is exactly ONE implementation of the atomic
// save (previously the two had drifted — this one lacked the secureperm
// hardening the path-explicit saver applies).  Kept for the directory-oriented
// call sites (chiefly tests) that predate the config-overridable cert paths.
func SaveCertificatesAtomic(certDir string, caCert, deviceCert, deviceKey []byte) error {
	return SaveCertificatesAtomicAt(CertFilePaths{
		CertFile: filepath.Join(certDir, "device.crt"),
		KeyFile:  filepath.Join(certDir, "device.key"),
		CAFile:   filepath.Join(certDir, "ca.crt"),
	}, caCert, deviceCert, deviceKey)
}

// writeAndSync writes data to path with the given mode and fsyncs it to disk
// before returning, so the bytes are durable before the caller renames the
// file into place.
func writeAndSync(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// trustKey is the shared on-disk shape of every per-channel signing-trust
// record (license-map, install-gate, vuln-map).  All three persist the same
// {key_id, pubkey_b64} pair with identical JSON tags, so saveTrustKey /
// loadTrustKey carry the one copy of the read/write/validate logic and the
// exported per-channel types are byte-identical layouts of this struct — a
// pointer conversion between them is legal and zero-copy.
type trustKey struct {
	KeyID     string `json:"key_id"`
	PubKeyB64 string `json:"pubkey_b64"`
}

// saveTrustKey persists a {key_id, pubkey_b64} trust record to
// certDir/filename.  Empty keyID or pubKeyB64 is a silent no-op (returns nil)
// so a server that has not provisioned a given signing channel never blanks an
// existing trust file with zeroes.  File mode 0o600, parent dir 0o700 — the
// same modes all three channels used before extraction.
func saveTrustKey(certDir, filename, keyID, pubKeyB64 string) error {
	if keyID == "" || pubKeyB64 == "" {
		return nil
	}
	if err := os.MkdirAll(certDir, 0o700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}
	data, err := json.Marshal(trustKey{KeyID: keyID, PubKeyB64: pubKeyB64})
	if err != nil {
		return fmt.Errorf("marshal trust record: %w", err)
	}
	path := filepath.Join(certDir, filename)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filename, err)
	}
	return nil
}

// loadTrustKey reads the trust record at certDir/filename.  Returns (nil, nil)
// when the file does not exist yet (fresh install pre-register); a decode error
// or a partial record (either field empty) returns (nil, err) so callers can
// log and skip verification rather than crash.
func loadTrustKey(certDir, filename string) (*trustKey, error) {
	path := filepath.Join(certDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", filename, err)
	}
	var trust trustKey
	if err := json.Unmarshal(data, &trust); err != nil {
		return nil, fmt.Errorf("decode %s: %w", filename, err)
	}
	if trust.KeyID == "" || trust.PubKeyB64 == "" {
		return nil, fmt.Errorf("%s: key_id and pubkey_b64 both required", filename)
	}
	return &trust, nil
}

// licenseMapTrustFile is the on-disk filename where the agent persists
// the server's license-map signing pubkey, discovered at register time.
// Stored in the same directory as the mTLS certs because trust for
// both is anchored to the same TLS-fingerprint bootstrap.
const licenseMapTrustFile = "license_map_trust.json"

// LicenseMapTrust is the persisted shape of the trusted key learned
// during /register.  KeyID identifies which pinned entry envelopes
// set; PubKeyB64 is the raw 32-byte ed25519 public key, base64-encoded
// (the same encoding the agent's scanner/trustkeys.go consumes).
type LicenseMapTrust struct {
	KeyID     string `json:"key_id"`
	PubKeyB64 string `json:"pubkey_b64"`
}

// SaveLicenseMapTrust persists the pubkey returned by /register to
// certDir/license_map_trust.json.  Absent/empty key just writes nothing
// and returns nil — the agent treats license-map as unavailable.
func SaveLicenseMapTrust(certDir, keyID, pubKeyB64 string) error {
	return saveTrustKey(certDir, licenseMapTrustFile, keyID, pubKeyB64)
}

// LoadLicenseMapTrust returns the persisted pubkey, or (nil, nil) if
// no trust file exists yet (fresh install pre-register).  Any decode
// error returns (nil, err) so callers can log and continue without
// license-map verification.
func LoadLicenseMapTrust(certDir string) (*LicenseMapTrust, error) {
	t, err := loadTrustKey(certDir, licenseMapTrustFile)
	if err != nil || t == nil {
		return nil, err
	}
	return (*LicenseMapTrust)(t), nil
}

// installGateTrustFile is the on-disk filename where the agent
// persists the server's install-gate signing pubkey, learned at
// /register.  Co-located with the mTLS certs because trust for both
// is anchored to the same TLS-fingerprint bootstrap.  Separate file
// from the license-map trust file so a key rotation on one channel
// does not touch the other.
const installGateTrustFile = "install_gate_trust.json"

// InstallGateTrust is the persisted shape of the trusted install-
// gate signing key learned during /register.  “KeyID“ identifies
// which pinned entry envelopes set; “PubKeyB64“ is the raw 32-byte
// ed25519 public key, base64-encoded.
type InstallGateTrust struct {
	KeyID     string `json:"key_id"`
	PubKeyB64 string `json:"pubkey_b64"`
}

// SaveInstallGateTrust persists the install-gate pubkey returned by
// /register to “certDir/install_gate_trust.json“.  Empty fields are
// silently no-op'd so a server that has not provisioned an install-
// gate key (e.g. older deployments) does not blank out an existing
// trust file with zeroes.
func SaveInstallGateTrust(certDir, keyID, pubKeyB64 string) error {
	return saveTrustKey(certDir, installGateTrustFile, keyID, pubKeyB64)
}

// LoadInstallGateTrust returns the persisted install-gate pubkey, or
// (nil, nil) if no trust file exists yet (fresh install pre-register).
// Decode errors return (nil, err) so callers can log and skip
// install-gate verification rather than crash.
func LoadInstallGateTrust(certDir string) (*InstallGateTrust, error) {
	t, err := loadTrustKey(certDir, installGateTrustFile)
	if err != nil || t == nil {
		return nil, err
	}
	return (*InstallGateTrust)(t), nil
}

// vulnMapTrustFile is the on-disk filename where the agent persists
// the server's vuln-map signing pubkey, learned at /register.
// Co-located with the mTLS certs because trust for the bundle rides
// on the same TLS-fingerprint bootstrap that issued the cert.
// Separate from the license-map and install-gate trust files so a
// key rotation on one channel never touches the others — same
// independence story those two have between each other.
const vulnMapTrustFile = "vuln_map_trust.json"

// VulnMapTrust is the persisted shape of the trusted vuln-map signing
// key learned during /register.  “KeyID“ identifies which pinned
// entry envelopes set; “PubKeyB64“ is the raw 32-byte ed25519
// public key, base64-encoded.  Same wire shape as the license-map
// and install-gate trust records — kept identical so a future
// rotation/refresh tool can read all three by name.
type VulnMapTrust struct {
	KeyID     string `json:"key_id"`
	PubKeyB64 string `json:"pubkey_b64"`
}

// SaveVulnMapTrust persists the vuln-map pubkey returned by /register
// to “certDir/vuln_map_trust.json“.  Empty fields are silently
// no-op'd so a server that has not provisioned a vuln-map signing
// key (older deployments, or air-gap operators who haven't imported
// an NVD bundle yet) does not blank out an existing trust file
// with zeroes.
func SaveVulnMapTrust(certDir, keyID, pubKeyB64 string) error {
	return saveTrustKey(certDir, vulnMapTrustFile, keyID, pubKeyB64)
}

// LoadVulnMapTrust returns the persisted vuln-map pubkey, or
// (nil, nil) if no trust file exists yet (fresh install pre-register,
// or a server that doesn't ship a vuln-map signing key).  Decode
// errors return (nil, err) so callers can log and skip vuln-map
// envelope verification rather than crash.
//
// This is the read half of the register-time trust-on-first-use pin for the
// offline-CVE (vuln-map) channel.  It has no production caller YET: the
// vuln-map fetch/verify consumer is not built, whereas SaveVulnMapTrust IS
// wired into register/renew (see cmd/sentari-agent/cert_lifecycle.go) so the
// pubkey is pinned the moment it rides in on the bootstrap TLS fingerprint —
// a one-shot that cannot be re-derived later without re-registration.  Kept
// (rather than deleted) as the deliberate, test-covered read counterpart the
// forthcoming vuln-map verify path will call, mirroring how
// LoadLicenseMapTrust / LoadInstallGateTrust are consumed today.
func LoadVulnMapTrust(certDir string) (*VulnMapTrust, error) {
	t, err := loadTrustKey(certDir, vulnMapTrustFile)
	if err != nil || t == nil {
		return nil, err
	}
	return (*VulnMapTrust)(t), nil
}

// SaveDeviceID persists the server-assigned device UUID to a file so the agent
// can include it in subsequent scan uploads.
func SaveDeviceID(certDir, deviceID string) error {
	if deviceID == "" {
		return fmt.Errorf("SaveDeviceID: deviceID must not be empty")
	}
	path := filepath.Join(certDir, "device_id")
	return os.WriteFile(path, []byte(deviceID), 0600)
}

// LoadDeviceID reads the persisted device UUID. Returns an empty string if the
// file does not exist or cannot be read.
func LoadDeviceID(certDir string) string {
	data, err := os.ReadFile(filepath.Join(certDir, "device_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// maxScanRecords is the global ceiling on the combined number of variable-
// cardinality records a single scan upload may carry — len(Packages) +
// len(DepEdges) + len(LicenseEvidence) + len(SupplyChainSignals).  A pathological
// host (a build box with millions of transitive dep-edges, or a runaway
// license-evidence explosion) would otherwise buffer and JSON-marshal an
// unbounded payload entirely in memory, risking OOM on the agent before the
// server ever applies its own 413 limit.  The cap mirrors the merged-tree entry
// cap in scanner/containers/materialize.go: when it trips, the payload is
// truncated to the budget and a single non-fatal ScanError is appended so the
// truncation is OBSERVABLE server-side, never silent.
//
// 5,000,000 records is deliberately generous — a realistic fleet host reports a
// few thousand packages and at most low-hundreds-of-thousands of dep-edges, so
// this never trips in practice while still bounding the pathological case to a
// payload on the order of a few hundred MiB rather than unbounded.
var maxScanRecords = 5_000_000

// enforceScanRecordBudget caps the combined variable-cardinality record count of
// a scan result at maxScanRecords, mutating result in place.  Slices are trimmed
// in priority order (Packages first — the primary inventory signal — then
// DepEdges, LicenseEvidence, SupplyChainSignals) so the most valuable data
// survives truncation, and a single ScanError is appended describing what was
// dropped.  A result already within budget is left untouched (no ScanError).
func enforceScanRecordBudget(result *scanner.ScanResult) {
	total := len(result.Packages) + len(result.DepEdges) +
		len(result.LicenseEvidence) + len(result.SupplyChainSignals)
	if total <= maxScanRecords {
		return
	}

	remaining := maxScanRecords
	// Trim each slice to the budget still remaining, highest-priority first.
	trim := func(n int) int {
		if n <= remaining {
			remaining -= n
			return n
		}
		keep := remaining
		remaining = 0
		return keep
	}
	result.Packages = result.Packages[:trim(len(result.Packages))]
	result.DepEdges = result.DepEdges[:trim(len(result.DepEdges))]
	result.LicenseEvidence = result.LicenseEvidence[:trim(len(result.LicenseEvidence))]
	result.SupplyChainSignals = result.SupplyChainSignals[:trim(len(result.SupplyChainSignals))]

	result.Errors = append(result.Errors, scanner.ScanError{
		Path: result.Hostname,
		Error: fmt.Sprintf(
			"scan payload truncated: %d combined records (packages+dep_edges+license_evidence+supply_chain_signals) exceeds the %d-record upload budget; kept the highest-priority records and dropped the remainder to bound agent memory",
			total, maxScanRecords),
		Timestamp: time.Now().UTC(),
	})
}

// UploadScan sends scan results to the server.  Retries on transient
// network / 429 / 5xx via doRequest.  The caller's ctx must carry the
// scan-cycle request_id so the upload joins the correlation chain.
func (c *Client) UploadScan(ctx context.Context, result *scanner.ScanResult) error {
	// Bound peak memory: cap the combined record count before assembling and
	// marshalling the payload, appending an observable truncation ScanError if
	// the pathological ceiling is hit.
	enforceScanRecordBudget(result)

	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal scan result: %w", err)
	}

	resp, err := c.doRequest(ctx, "upload_scan", func(ctx context.Context) (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/v1/agent/scan", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", "application/json")
		// Payload version marker.  The server uses this to distinguish v2
		// payloads (no dep_edges/lockfiles/supply_chain_signals/license_
		// evidence) from v3 ones, so missing v3 fields on a v3-tagged payload
		// mean "agent looked and found nothing" rather than "agent doesn't
		// speak v3".  The header is ADVISORY (the server shape-gates each
		// block); we advertise "4" only when this scan actually carries a v4
		// block (hardening_observations), else "3".  Older servers tolerate
		// either (unknown headers are ignored per HTTP semantics).
		payloadVersion := "3"
		if len(result.HardeningObservations) > 0 {
			payloadVersion = "4"
		}
		r.Header.Set("X-Sentari-Payload-Version", payloadVersion)
		return r, nil
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return &HTTPStatusError{
			Op:         "scan upload",
			StatusCode: resp.StatusCode,
			Body:       truncateBytes(respBody, maxErrorBodyLog),
		}
	}

	return nil
}

// AuditShipMaxBatch is the server-enforced cap on entries per audit-ship
// request (docs/contracts/agent-audit-ship-v1.json, "maxItems": 10000).
const AuditShipMaxBatch = 10000

type auditShipEntry struct {
	EntryID     int    `json:"entry_id"`
	EventType   string `json:"event_type"`
	Detail      string `json:"detail"`
	ContentHash string `json:"content_hash"`
	PrevHash    string `json:"prev_hash"`
	CreatedAt   string `json:"created_at"`
	// Encoding scheme of content_hash (1 = legacy plain concat, 2 = length-
	// prefixed). Always emitted (no omitempty) so the server never has to guess:
	// an entry from a pre-v2 agent row carries 1, a new row carries 2.
	HashVersion int `json:"hash_version"`
}

type auditShipRequest struct {
	DeviceID string           `json:"device_id"`
	Entries  []auditShipEntry `json:"entries"`
}

// ShipAudit ships a batch of the agent's local append-only audit entries to the
// server's re-anchoring endpoint (POST /api/v1/agent/audit-log, contract
// agent-audit-ship-v1). “entries“ are the raw rows from
// audit.AuditLog.UnshippedEntries(); the server independently re-verifies the
// SHA-256 hash chain and stores them as append-only forensic evidence — the
// real tamper-evidence story for a device that may itself be compromised.
//
// Returns the highest entry_id accepted so the caller can MarkShipped(maxID).
// The server always answers 202 (even on a detected chain anomaly — the
// evidence is preserved and an alert raised server-side), so any non-202 is a
// transport/auth failure and the entries stay unshipped for the next cycle. A
// batch larger than AuditShipMaxBatch is truncated to the cap; the caller loops
// to drain the remainder.
func (c *Client) ShipAudit(ctx context.Context, deviceID string, entries []map[string]string) (int, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	if len(entries) > AuditShipMaxBatch {
		entries = entries[:AuditShipMaxBatch]
	}

	payload := auditShipRequest{DeviceID: deviceID, Entries: make([]auditShipEntry, 0, len(entries))}
	maxID := 0
	for _, e := range entries {
		id, err := strconv.Atoi(e["id"])
		if err != nil {
			return 0, fmt.Errorf("audit ship: bad entry id %q: %w", e["id"], err)
		}
		if id > maxID {
			maxID = id
		}
		// hash_version is absent on maps built by older code paths; default to
		// scheme 1 (the legacy plain-concat encoding) so the server recomputes
		// those correctly.
		hashVersion := 1
		if hv, ok := e["hash_version"]; ok && hv != "" {
			parsed, err := strconv.Atoi(hv)
			if err != nil {
				return 0, fmt.Errorf("audit ship: bad entry hash_version %q: %w", hv, err)
			}
			hashVersion = parsed
		}
		payload.Entries = append(payload.Entries, auditShipEntry{
			EntryID:     id,
			EventType:   e["event_type"],
			Detail:      e["detail"],
			ContentHash: e["content_hash"],
			PrevHash:    e["prev_hash"],
			CreatedAt:   e["created_at"],
			HashVersion: hashVersion,
		})
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal audit ship payload: %w", err)
	}

	resp, err := c.doRequest(ctx, "ship_audit", func(ctx context.Context) (*http.Request, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/v1/agent/audit-log", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", "application/json")
		return r, nil
	})
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return 0, fmt.Errorf("audit ship failed (HTTP %d): %s", resp.StatusCode, truncateBytes(respBody, maxErrorBodyLog))
	}

	return maxID, nil
}

// PollConfig fetches the latest agent configuration from the server.
func (c *Client) PollConfig(ctx context.Context) (*AgentConfig, error) {
	resp, err := c.doRequest(ctx, "poll_config", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/api/v1/agent/config", nil)
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config poll failed (HTTP %d)", resp.StatusCode)
	}

	var cfg AgentConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	return &cfg, nil
}

// FetchLicenseMap fetches the latest license mapping table from the
// server.  The response is a signed envelope; this function reads the
// raw bytes, verifies the ed25519 signature against a pinned public
// key, and returns the verified LicenseMap plus the raw envelope bytes
// so the caller can persist them for offline re-use.
//
// Returns (nil, nil, nil) when the server's version is not newer than
// currentVersion — no update needed, no error.
func (c *Client) FetchLicenseMap(ctx context.Context, currentVersion int) (*scanner.LicenseMap, []byte, error) {
	resp, err := c.doRequest(ctx, "fetch_license_map", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/api/v1/agent/license-map", nil)
	})
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("license-map fetch: status %d", resp.StatusCode)
	}

	// Read the full envelope bytes (capped) so we can both verify the
	// signature AND cache the envelope for later re-verification.
	body, err := io.ReadAll(io.LimitReader(resp.Body, scanner.MaxMapPayloadBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("license-map read: %w", err)
	}
	if len(body) > scanner.MaxMapPayloadBytes {
		return nil, nil, fmt.Errorf("license-map fetch: response exceeds size cap")
	}

	m, err := scanner.VerifyMapEnvelope(body)
	if err != nil {
		return nil, nil, fmt.Errorf("license-map verify: %w", err)
	}

	if m.Version <= currentVersion {
		return nil, nil, nil // no update needed
	}

	return m, body, nil
}

// FetchInstallGateMap fetches the latest install-gate policy map from
// the server.  The response is a signed envelope; this function reads
// the raw bytes, verifies the ed25519 signature against the pinned
// install-gate public key, and returns the verified
// “InstallGateMap“ plus the raw envelope bytes so the caller can
// persist them for offline re-use.
//
// Returns “(nil, nil, nil)“ when the server's version is not newer
// than “currentVersion“ — no update needed, no error.  Mirrors the
// license-map fetch contract.
func (c *Client) FetchInstallGateMap(ctx context.Context, currentVersion int) (*scanner.InstallGateMap, []byte, error) {
	resp, err := c.doRequest(ctx, "fetch_install_gate", func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/api/v1/agent/policy-map", nil)
	})
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 404 + X-Sentari-Install-Gate-Disabled: true is an explicit
		// tenant-wide disable signal.  Surface it as a distinct error
		// so the main loop can tear down host configs immediately
		// (a plain/transient 404 instead keeps the last-good cached
		// policy enforced — fail-closed; there is no time-based grace).
		if isInstallGateServerDisabled(resp) {
			return nil, nil, ErrInstallGateServerDisabled
		}
		return nil, nil, fmt.Errorf("install-gate fetch: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, scanner.MaxInstallGatePayloadBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("install-gate read: %w", err)
	}
	if len(body) > scanner.MaxInstallGatePayloadBytes {
		return nil, nil, fmt.Errorf("install-gate fetch: response exceeds size cap")
	}

	m, err := scanner.VerifyInstallGateEnvelope(body)
	if err != nil {
		return nil, nil, fmt.Errorf("install-gate verify: %w", err)
	}

	if m.Version <= currentVersion {
		return nil, nil, nil
	}

	return m, body, nil
}

// truncateBytes returns s as a string, truncated to maxLen bytes with an
// ellipsis marker appended if truncation occurred.  Used to prevent server
// error bodies (which may contain stack traces or internal details) from
// flooding agent log output.
func truncateBytes(s []byte, maxLen int) string {
	if len(s) <= maxLen {
		return string(s)
	}
	return string(s[:maxLen]) + "... [truncated]"
}
