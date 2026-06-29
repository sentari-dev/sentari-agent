package containers

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestReadCappedFile_RefusesSymlink — Fix #3.  readCappedFile is the
// shared metadata reader behind cache-id / mount-id / image-config /
// container-config reads.  It must refuse a symlinked target so a
// malicious package planting ``cache-id -> /etc/shadow`` can't
// exfiltrate host content into a container-tagged record, and must
// avoid the os.Stat+os.ReadFile TOCTOU.  Routing through safeio gives
// us both (O_NOFOLLOW + fd-based stat).
func TestReadCappedFile_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevation on Windows test runners")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("top-secret-host-content"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	link := filepath.Join(dir, "cache-id")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	data, err := readCappedFile(link, 1<<20)
	if err == nil {
		t.Fatalf("expected readCappedFile to refuse symlink; got data=%q", data)
	}
	if strings.Contains(string(data), "top-secret") {
		t.Errorf("symlinked host content leaked through readCappedFile: %q", data)
	}
}

// TestReadCappedFile_RefusesOversize — Fix #3.  An oversize file must
// be refused outright (never partially read) — this is the
// disk/memory-exhaustion guard for repositories.json and friends.
func TestReadCappedFile_RefusesOversize(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "repositories.json")
	if err := os.WriteFile(big, make([]byte, 2048), 0o644); err != nil {
		t.Fatalf("write big: %v", err)
	}
	if _, err := readCappedFile(big, 1024); err == nil {
		t.Fatalf("expected readCappedFile to refuse a file over the cap")
	}
}

// TestReadRepositories_RefusesOversize — Fix #3, end-to-end through
// the repositories.json reader.  An oversize repositories.json (a
// hostile or corrupt index) must be refused rather than slurped whole.
func TestReadRepositories_RefusesOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "repositories.json")
	// Well past the repositories.json cap.
	if err := os.WriteFile(path, make([]byte, repositoriesJSONMaxBytes+1), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readRepositories(path); err == nil {
		t.Fatalf("expected readRepositories to refuse an oversize index")
	}
}

// TestReadRepositories_RefusesSymlink — Fix #3.  A symlinked
// repositories.json must be refused (no host-content follow).
func TestReadRepositories_RefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevation on Windows test runners")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(secret, []byte(`{"Repositories":{}}`), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	link := filepath.Join(dir, "repositories.json")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := readRepositories(link); err == nil {
		t.Fatalf("expected readRepositories to refuse a symlinked index")
	}
}

// TestReadCappedFile_MissingPassesThrough — readRepositories relies on
// os.IsNotExist branching to treat a missing index as "no tags".  The
// safeio-routed readCappedFile must still surface a not-exist error
// that os.IsNotExist recognises so that branch keeps working.
func TestReadCappedFile_MissingPassesThrough(t *testing.T) {
	dir := t.TempDir()
	_, err := readCappedFile(filepath.Join(dir, "absent"), 1<<20)
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist to recognise the error, got: %v", err)
	}
}
