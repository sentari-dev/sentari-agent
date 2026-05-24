package installgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestRedTeam_WriteAndSyncRefusesSymlinkTarget models the LPE attack
// the audit flagged: a local attacker who can write to the config's
// parent directory plants the tmp target as a symlink to a root-owned
// sentinel file.  Pre-fix, writeAndSync opened its target with
// O_CREATE|O_WRONLY|O_TRUNC (no O_EXCL, no O_NOFOLLOW); the agent —
// running as root for system-scope configs — would follow the symlink
// and truncate+overwrite the sentinel.  The TOCTOU window between
// WriteAtomic's pre-write os.Remove and the open is the real exploit
// surface, so we exercise writeAndSync directly: it must refuse to
// write through a symlink leaf (O_EXCL refuses any pre-existing inode;
// O_NOFOLLOW additionally refuses a symlink on unix).
func TestRedTeam_WriteAndSyncRefusesSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires symlink creation privilege unavailable on default Windows")
	}
	dir := t.TempDir()

	// Sentinel = the "root-owned" file the attacker wants overwritten.
	sentinel := filepath.Join(dir, "sentinel-root-owned")
	const sentinelMarker = "DO-NOT-OVERWRITE-ROOT-FILE"
	if err := os.WriteFile(sentinel, []byte(sentinelMarker), 0o644); err != nil {
		t.Fatal(err)
	}

	// Attacker plants the write target as a symlink to the sentinel.
	target := filepath.Join(dir, "pip.conf.sentari-tmp")
	if err := os.Symlink(sentinel, target); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	// writeAndSync must refuse — the target inode already exists.
	err := writeAndSync(target, []byte("attacker-payload\n"), 0o644)
	if err == nil {
		t.Fatal("SECURITY: writeAndSync followed/clobbered a planted symlink target")
	}

	// The sentinel target MUST be unchanged.
	got, rerr := os.ReadFile(sentinel)
	if rerr != nil {
		t.Fatalf("sentinel unreadable after write (it was clobbered/removed): %v", rerr)
	}
	if string(got) != sentinelMarker {
		t.Fatalf("SECURITY: sentinel was overwritten through planted tmp symlink: got %q", got)
	}
}

// TestRedTeam_WriteAndSyncRefusesExistingFile guards the O_EXCL
// invariant directly: writeAndSync must refuse to open a target that
// already exists as a regular file (so a pre-planted inode can never
// be adopted as our write buffer).  WriteAtomic relies on this by
// generating a fresh random nonce path the attacker cannot predict.
func TestRedTeam_WriteAndSyncRefusesExistingFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pip.conf.sentari-tmp")
	if err := os.WriteFile(target, []byte("planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAndSync(target, []byte("x\n"), 0o644); err == nil {
		t.Fatal("writeAndSync overwrote a pre-existing target file (O_EXCL missing)")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "planted\n" {
		t.Errorf("pre-existing target was modified: got %q", got)
	}
}

// TestRedTeam_TmpFileExistingRegularNotFollowed guards the non-symlink
// variant: a planted *regular* file at the predictable tmp path must
// not be silently truncated and adopted as our write buffer in a way
// that lets a racing attacker swap it.  With O_EXCL + a random nonce
// the planted regular file is irrelevant; the real config still lands
// and no stale predictable tmp survives.
func TestRedTeam_TmpFileExistingRegularNotFollowed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	plantedTmp := path + ".sentari-tmp"
	if err := os.WriteFile(plantedTmp, []byte("attacker-controlled\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const body = "# Managed by Sentari\nindex-url=x\n"
	changed, err := WriteAtomic(newOpts(path, []byte(body)))
	if err != nil {
		t.Fatalf("WriteAtomic over planted regular tmp: %v", err)
	}
	if !changed {
		t.Error("expected changed=true")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if string(got) != body {
		t.Errorf("config body mismatch: got %q", got)
	}
	// No predictable nonce-free tmp may linger.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sentari-tmp") {
			t.Errorf("predictable .sentari-tmp survived the write: %s", e.Name())
		}
	}
}

// TestRedTeam_ConfigPathSymlinkNotReadOrBackedUp models the pre-write
// read attack: the config path itself (e.g. ``/etc/pip.conf``) is a
// symlink to a sensitive root-owned file like /etc/shadow.  Pre-fix
// the writer's pre-write reads (isSentariManaged, readBoundedIfExists,
// backupOriginal's source open) all used os.Open and FOLLOWED the
// symlink — so the agent would (a) read the sensitive target to decide
// "managed?" and (b) COPY its contents into a world-discoverable
// ``.sentari-backup-*`` file.  Post-fix every pre-write read routes
// through safeio, which refuses a symlink leaf: WriteAtomic must error
// out and create NO backup containing the secret.
func TestRedTeam_ConfigPathSymlinkNotReadOrBackedUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires symlink creation privilege unavailable on default Windows")
	}
	dir := t.TempDir()

	secret := filepath.Join(dir, "shadow")
	const secretMarker = "root:$6$DO-NOT-EXFILTRATE"
	if err := os.WriteFile(secret, []byte(secretMarker), 0o600); err != nil {
		t.Fatal(err)
	}

	// The config path is a symlink to the secret.
	configPath := filepath.Join(dir, "pip.conf")
	if err := os.Symlink(secret, configPath); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	// Attempt a Sentari write at the symlinked path.  Different content
	// would normally trigger the backup-then-overwrite path.
	_, err := WriteAtomic(WriteOptions{
		Path:     configPath,
		Content:  []byte("# Managed by Sentari\nindex-url=x\n"),
		FileMode: 0o644,
		Now:      time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("SECURITY: WriteAtomic acted on a symlinked config path instead of refusing")
	}

	// No backup file may exist anywhere in the dir, and certainly none
	// containing the secret.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "sentari-backup") {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			t.Fatalf("SECURITY: backup file %s created from symlinked config (content=%q)", e.Name(), b)
		}
	}

	// The secret target must be intact (never truncated/overwritten).
	got, _ := os.ReadFile(secret)
	if string(got) != secretMarker {
		t.Fatalf("SECURITY: secret target modified through symlinked config path: %q", got)
	}
}
