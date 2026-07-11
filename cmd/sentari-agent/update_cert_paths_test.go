package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/config"
)

// TestResolveUpdateCertPaths_ConfigOverrideWins verifies that an explicit
// [server] cert_file/key_file/ca_cert_file in agent.conf is honoured by the
// self-update cert-path resolution, rather than the legacy dataDir/certs
// convention.  This is the resolution the registration gate existence-checks.
func TestResolveUpdateCertPaths_ConfigOverrideWins(t *testing.T) {
	dataDir := t.TempDir()
	customCert := "/etc/pki/sentari/leaf.pem"
	customKey := "/etc/pki/sentari/leaf.key"
	customCA := "/etc/pki/sentari/root.pem"

	cfg := config.AgentConfig{}
	cfg.Server.CertFile = customCert
	cfg.Server.KeyFile = customKey
	cfg.Server.CACertFile = customCA

	certDir, paths := resolveUpdateCertPaths(cfg, dataDir)

	if paths.CertFile != customCert {
		t.Errorf("CertFile: got %q, want overridden %q", paths.CertFile, customCert)
	}
	if paths.KeyFile != customKey {
		t.Errorf("KeyFile: got %q, want overridden %q", paths.KeyFile, customKey)
	}
	if paths.CAFile != customCA {
		t.Errorf("CAFile: got %q, want overridden %q", paths.CAFile, customCA)
	}
	// certDir is still the conventional dir (used for trust-file loads).
	if want := filepath.Join(dataDir, "certs"); certDir != want {
		t.Errorf("certDir: got %q, want %q", certDir, want)
	}
}

// TestResolveUpdateCertPaths_FallbackToCertDir verifies the fallback to the
// dataDir/certs/device.* + ca.crt convention when no override is configured.
func TestResolveUpdateCertPaths_FallbackToCertDir(t *testing.T) {
	dataDir := t.TempDir()
	certDir, paths := resolveUpdateCertPaths(config.AgentConfig{}, dataDir)

	wantCertDir := filepath.Join(dataDir, "certs")
	if certDir != wantCertDir {
		t.Fatalf("certDir: got %q, want %q", certDir, wantCertDir)
	}
	if want := filepath.Join(wantCertDir, "device.crt"); paths.CertFile != want {
		t.Errorf("CertFile fallback: got %q, want %q", paths.CertFile, want)
	}
	if want := filepath.Join(wantCertDir, "device.key"); paths.KeyFile != want {
		t.Errorf("KeyFile fallback: got %q, want %q", paths.KeyFile, want)
	}
	if want := filepath.Join(wantCertDir, "ca.crt"); paths.CAFile != want {
		t.Errorf("CAFile fallback: got %q, want %q", paths.CAFile, want)
	}
}

// TestRunUpdate_GateChecksOverriddenCertPaths is the regression guard for
// security-3 / quality-2: with valid certs present ONLY at the config-overridden
// paths (and the legacy dataDir/certs dir empty), the registration gate must
// treat the agent as registered and proceed past it.  Before the fix the gate
// used comms.CertsExist(certDir) with fixed filenames, so it never saw the
// overridden certs and wrongly reported "not registered".
func TestRunUpdate_GateChecksOverriddenCertPaths(t *testing.T) {
	dataDir := t.TempDir()   // its certs/ subdir stays empty
	customDir := t.TempDir() // certs live here, under non-conventional names
	certFile := filepath.Join(customDir, "leaf.pem")
	keyFile := filepath.Join(customDir, "leaf.key")
	caFile := filepath.Join(customDir, "root.pem")
	for _, p := range []string{certFile, keyFile, caFile} {
		if err := os.WriteFile(p, []byte("dummy-pem"), 0o600); err != nil {
			t.Fatalf("seed cert material %s: %v", p, err)
		}
	}

	cfg := config.AgentConfig{}
	cfg.Server.URL = "https://server.example:8443" // non-empty so we clear the URL gate
	cfg.Server.CertFile = certFile
	cfg.Server.KeyFile = keyFile
	cfg.Server.CACertFile = caFile

	stderr := captureStderr(t, func() {
		// updateModeCheck stops (returns 1) at the install-gate-trust gate,
		// which is BEFORE any network use, because certDir has no trust file.
		_ = runUpdate(updateModeCheck, cfg, "", dataDir, "")
	})

	if strings.Contains(stderr, "not registered") {
		t.Fatalf("registration gate used legacy fixed-filename check and missed "+
			"config-overridden certs; stderr: %s", stderr)
	}
	// Positive confirmation we advanced past the registration gate to the next one.
	if !strings.Contains(stderr, "Install-gate trust is not provisioned") {
		t.Fatalf("expected to reach the install-gate-trust gate after passing the "+
			"registration gate; stderr: %s", stderr)
	}
}

// captureStderr redirects os.Stderr for the duration of fn and returns what was
// written.  runUpdate writes operator diagnostics directly to os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- string(buf)
	}()
	fn()
	_ = w.Close()
	os.Stderr = orig
	out := <-done
	_ = r.Close()
	return out
}
