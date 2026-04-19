// Package comms provides the mTLS HTTPS client for agent-server communication.
// The agent uses a pull model: it initiates all connections outbound.
// No inbound ports are required on endpoints.
package comms

import (
	"bytes"
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

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
// Sprint 3: the server issues a real mTLS device certificate on registration.
type RegisterResponse struct {
	DeviceID   string `json:"device_id"`
	CACert     string `json:"ca_cert"`     // PEM CA certificate — pin for subsequent connections
	DeviceCert string `json:"device_cert"` // PEM device certificate
	DeviceKey  string `json:"device_key"`  // Deprecated: unused since CSR-based registration; kept for backward compat.
	Message    string `json:"message"`
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
}

// NewClient creates a new mTLS client. If cert/key files are not provided,
// it creates a plain TLS client (no client cert) for initial registration only.
// If ProxyConfig.HTTPSProxy is set, all requests are routed through the proxy.
// If HTTPSProxy is empty, the default Go behavior applies (respects HTTP_PROXY/
// HTTPS_PROXY environment variables).
func NewClient(cfg ClientConfig) (*Client, error) {
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

	// Pin the server TLS certificate by SHA-256 fingerprint during bootstrap.
	// This prevents MITM attacks when the agent has not yet received the CA
	// certificate from the server.
	if cfg.BootstrapFingerprint != "" {
		expected := strings.ToLower(strings.ReplaceAll(cfg.BootstrapFingerprint, ":", ""))
		tlsConfig.InsecureSkipVerify = true // We verify manually via fingerprint.
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

	// Load CA certificate for server verification (certificate pinning).
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

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
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
		serverURL: cfg.ServerURL,
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

// buildProxyFunc creates an http.Transport.Proxy function from the ProxyConfig.
// It parses the proxy URL, injects auth credentials (AuthUser + AuthPassFile
// take precedence over credentials embedded in the URL), and respects the
// NoProxy bypass list.
func buildProxyFunc(pc ProxyConfig) (func(*http.Request) (*url.URL, error), error) {
	proxyURL, err := url.Parse(pc.HTTPSProxy)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL %q: %w", pc.HTTPSProxy, err)
	}

	if proxyURL.Scheme == "" {
		return nil, fmt.Errorf("proxy URL %q missing scheme (expected http:// or https://)", pc.HTTPSProxy)
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

// Register sends an agent registration request to the server and returns the
// issued device certificate bundle along with the locally-generated private key.
func (c *Client) Register(hostname string) (*RegisterResponse, []byte, error) {
	return c.RegisterWithToken(hostname, "")
}

// RegisterWithToken sends a registration request including an enrollment token.
// The agent generates its own ECDSA P-256 keypair and sends a CSR to the server.
// The server signs the CSR and returns the device certificate + CA certificate.
// The private key never leaves the agent.
func (c *Client) RegisterWithToken(hostname, enrollmentToken string) (*RegisterResponse, []byte, error) {
	// Generate ECDSA P-256 keypair on the agent.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate device key: %w", err)
	}

	// Build a CSR with the hostname as CN.
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
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Encode private key to PEM (kept locally).
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal device key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

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

	resp, err := c.httpClient.Post(
		c.serverURL+"/api/v1/agent/register",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("registration request: %w", err)
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

	return &regResp, keyPEM, nil
}

// SaveCertificates writes the CA cert, device cert, and device key to certDir.
// File permissions: ca.crt and device.crt are 0644; device.key is 0600.
func SaveCertificates(certDir string, caCert, deviceCert, deviceKey []byte) error {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	type certFile struct {
		name string
		data []byte
		mode os.FileMode
	}
	for _, f := range []certFile{
		{"ca.crt", caCert, 0644},
		{"device.crt", deviceCert, 0644},
		{"device.key", deviceKey, 0600},
	} {
		path := filepath.Join(certDir, f.name)
		if err := os.WriteFile(path, f.data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}

	return nil
}

// CertsExist returns true if all three certificate files are present in certDir.
func CertsExist(certDir string) bool {
	for _, name := range []string{"ca.crt", "device.crt", "device.key"} {
		if _, err := os.Stat(filepath.Join(certDir, name)); err != nil {
			return false
		}
	}
	return true
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

// UploadScan sends scan results to the server.
func (c *Client) UploadScan(result *scanner.ScanResult) error {
	body, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal scan result: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.serverURL+"/api/v1/agent/scan",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("scan upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return fmt.Errorf("scan upload failed (HTTP %d): %s", resp.StatusCode, truncateBytes(respBody, maxErrorBodyLog))
	}

	return nil
}

// PollConfig fetches the latest agent configuration from the server.
func (c *Client) PollConfig() (*AgentConfig, error) {
	resp, err := c.httpClient.Get(c.serverURL + "/api/v1/agent/config")
	if err != nil {
		return nil, fmt.Errorf("config poll: %w", err)
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
// server.  The response is a signed envelope (ADR 0001); this function
// reads the raw bytes, verifies the ed25519 signature against a pinned
// public key, and returns the verified LicenseMap plus the raw
// envelope bytes so the caller can persist them for offline re-use.
//
// Returns (nil, nil, nil) when the server's version is not newer than
// currentVersion — no update needed, no error.
func (c *Client) FetchLicenseMap(currentVersion int) (*scanner.LicenseMap, []byte, error) {
	resp, err := c.httpClient.Get(c.serverURL + "/api/v1/agent/license-map")
	if err != nil {
		return nil, nil, fmt.Errorf("license-map fetch: %w", err)
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
