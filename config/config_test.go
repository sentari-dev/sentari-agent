package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadFromFile_UTF8BOM verifies that a config file carrying a leading
// UTF-8 BOM (U+FEFF), as written by Windows PowerShell 5.1's
// Set-Content -Encoding UTF8, parses identically to the BOM-less file.
func TestLoadFromFile_UTF8BOM(t *testing.T) {
	body := "# Sentari Agent Configuration\n[server]\nurl = https://example.test\n[scanner]\ninterval = 3600\n"

	plainPath := writeTempConfig(t, body)
	plain, err := LoadFromFile(plainPath)
	if err != nil {
		t.Fatalf("LoadFromFile (no BOM): %v", err)
	}

	dir := t.TempDir()
	bomPath := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(bomPath, append([]byte("\ufeff"), body...), 0o600); err != nil {
		t.Fatal(err)
	}
	withBOM, err := LoadFromFile(bomPath)
	if err != nil {
		t.Fatalf("LoadFromFile (with BOM): %v", err)
	}

	if withBOM.Server.URL != plain.Server.URL {
		t.Errorf("Server.URL: BOM=%q, plain=%q", withBOM.Server.URL, plain.Server.URL)
	}
	if withBOM.Server.URL != "https://example.test" {
		t.Errorf("Server.URL: got %q, want https://example.test", withBOM.Server.URL)
	}
	if withBOM.Scanner.Interval != plain.Scanner.Interval {
		t.Errorf("Scanner.Interval: BOM=%d, plain=%d", withBOM.Scanner.Interval, plain.Scanner.Interval)
	}
}

// TestDefaultConfig_ScanRootEmpty verifies that DefaultConfig leaves
// ScanRoot empty so the platform default resolves at scan time in
// scanner.NewRunner (/ on POSIX, C:\ on Windows).  Hardcoding "/" here
// made the Windows fallback dead code on config-less runs.
func TestDefaultConfig_ScanRootEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Scanner.ScanRoot != "" {
		t.Errorf("DefaultConfig ScanRoot: got %q, want empty (platform default resolves in scanner.NewRunner)", cfg.Scanner.ScanRoot)
	}
	// The other scanner defaults must remain intact.
	if cfg.Scanner.MaxDepth != 8 {
		t.Errorf("DefaultConfig MaxDepth: got %d, want 8", cfg.Scanner.MaxDepth)
	}
	if cfg.Scanner.Interval != 3600 {
		t.Errorf("DefaultConfig Interval: got %d, want 3600", cfg.Scanner.Interval)
	}
}

// TestDefaultConfig_MaxPendingScans verifies the offline-queue cap defaults to
// the cache constant (500) so a config-less agent keeps the built-in retention.
func TestDefaultConfig_MaxPendingScans(t *testing.T) {
	if got := DefaultConfig().Cache.MaxPendingScans; got != 500 {
		t.Errorf("DefaultConfig MaxPendingScans: got %d, want 500", got)
	}
}

// TestLoadFromFile_MaxPendingScans covers the [cache] max_pending_scans setting:
// a valid override parses, 0 is accepted (retention disabled), and a negative
// value is rejected.
func TestLoadFromFile_MaxPendingScans(t *testing.T) {
	valid := writeTempConfig(t, "[cache]\nmax_pending_scans = 2000\n")
	cfg, err := LoadFromFile(valid)
	if err != nil {
		t.Fatalf("LoadFromFile (valid): %v", err)
	}
	if cfg.Cache.MaxPendingScans != 2000 {
		t.Errorf("MaxPendingScans: got %d, want 2000", cfg.Cache.MaxPendingScans)
	}

	zero := writeTempConfig(t, "[cache]\nmax_pending_scans = 0\n")
	zcfg, err := LoadFromFile(zero)
	if err != nil {
		t.Fatalf("LoadFromFile (zero): %v", err)
	}
	if zcfg.Cache.MaxPendingScans != 0 {
		t.Errorf("MaxPendingScans (zero): got %d, want 0", zcfg.Cache.MaxPendingScans)
	}

	neg := writeTempConfig(t, "[cache]\nmax_pending_scans = -5\n")
	if _, err := LoadFromFile(neg); err == nil {
		t.Fatalf("LoadFromFile (negative): want error, got nil")
	}

	bad := writeTempConfig(t, "[cache]\nmax_pending_scans = notanint\n")
	if _, err := LoadFromFile(bad); err == nil {
		t.Fatalf("LoadFromFile (non-integer): want error, got nil")
	}
}

// TestDefaultConfig_MaxPendingBytes verifies the offline-queue byte cap defaults
// to the cache constant (512 MiB) so a config-less agent keeps the built-in cap.
func TestDefaultConfig_MaxPendingBytes(t *testing.T) {
	if got := DefaultConfig().Cache.MaxPendingBytes; got != 512<<20 {
		t.Errorf("DefaultConfig MaxPendingBytes: got %d, want %d", got, 512<<20)
	}
}

// TestLoadFromFile_MaxPendingBytes covers the [cache] max_pending_bytes setting:
// a valid override parses, 0 is accepted (byte cap disabled), and a negative
// value is rejected.
func TestLoadFromFile_MaxPendingBytes(t *testing.T) {
	valid := writeTempConfig(t, "[cache]\nmax_pending_bytes = 1073741824\n")
	cfg, err := LoadFromFile(valid)
	if err != nil {
		t.Fatalf("LoadFromFile (valid): %v", err)
	}
	if cfg.Cache.MaxPendingBytes != 1073741824 {
		t.Errorf("MaxPendingBytes: got %d, want 1073741824", cfg.Cache.MaxPendingBytes)
	}

	zero := writeTempConfig(t, "[cache]\nmax_pending_bytes = 0\n")
	zcfg, err := LoadFromFile(zero)
	if err != nil {
		t.Fatalf("LoadFromFile (zero): %v", err)
	}
	if zcfg.Cache.MaxPendingBytes != 0 {
		t.Errorf("MaxPendingBytes (zero): got %d, want 0", zcfg.Cache.MaxPendingBytes)
	}

	neg := writeTempConfig(t, "[cache]\nmax_pending_bytes = -5\n")
	if _, err := LoadFromFile(neg); err == nil {
		t.Fatalf("LoadFromFile (negative): want error, got nil")
	}

	bad := writeTempConfig(t, "[cache]\nmax_pending_bytes = notanint\n")
	if _, err := LoadFromFile(bad); err == nil {
		t.Fatalf("LoadFromFile (non-integer): want error, got nil")
	}
}

// TestDefaultConfig_MaxAuditBytes verifies the audit-log retention cap defaults
// to the bounded DefaultMaxAuditBytes (256 MiB) so a config-less enterprise
// agent bounds its audit log out of the box (audit.MaxAuditBytes's own default
// is 0/disabled; the agent wires this bounded value in at startup).
func TestDefaultConfig_MaxAuditBytes(t *testing.T) {
	if got := DefaultConfig().Audit.MaxAuditBytes; got != 256<<20 {
		t.Errorf("DefaultConfig MaxAuditBytes: got %d, want %d", got, 256<<20)
	}
	if DefaultMaxAuditBytes != 256<<20 {
		t.Errorf("DefaultMaxAuditBytes: got %d, want %d", DefaultMaxAuditBytes, 256<<20)
	}
}

// TestLoadFromFile_MaxAuditBytes covers the [audit] max_audit_bytes setting:
// a valid override parses, 0 is accepted (cap disabled), and a negative or
// non-integer value is rejected.
func TestLoadFromFile_MaxAuditBytes(t *testing.T) {
	valid := writeTempConfig(t, "[audit]\nmax_audit_bytes = 1073741824\n")
	cfg, err := LoadFromFile(valid)
	if err != nil {
		t.Fatalf("LoadFromFile (valid): %v", err)
	}
	if cfg.Audit.MaxAuditBytes != 1073741824 {
		t.Errorf("MaxAuditBytes: got %d, want 1073741824", cfg.Audit.MaxAuditBytes)
	}

	zero := writeTempConfig(t, "[audit]\nmax_audit_bytes = 0\n")
	zcfg, err := LoadFromFile(zero)
	if err != nil {
		t.Fatalf("LoadFromFile (zero): %v", err)
	}
	if zcfg.Audit.MaxAuditBytes != 0 {
		t.Errorf("MaxAuditBytes (zero): got %d, want 0", zcfg.Audit.MaxAuditBytes)
	}

	neg := writeTempConfig(t, "[audit]\nmax_audit_bytes = -5\n")
	if _, err := LoadFromFile(neg); err == nil {
		t.Fatalf("LoadFromFile (negative): want error, got nil")
	}

	bad := writeTempConfig(t, "[audit]\nmax_audit_bytes = notanint\n")
	if _, err := LoadFromFile(bad); err == nil {
		t.Fatalf("LoadFromFile (non-integer): want error, got nil")
	}
}
