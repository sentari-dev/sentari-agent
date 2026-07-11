//go:build unix

package jvm

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// scanDirTreeWithin runs scanDirTree in a goroutine and fails the test
// if it does not return within d — a scan that hangs on a FIFO is a
// fleet-wide DoS, so "does not hang" is itself an assertion.
func scanDirTreeWithin(t *testing.T, root string, d time.Duration) ([]scanner.PackageRecord, []scanner.ScanError) {
	t.Helper()
	type result struct {
		recs []scanner.PackageRecord
		errs []scanner.ScanError
	}
	done := make(chan result, 1)
	go func() {
		recs, errs := scanDirTree(context.Background(), root)
		done <- result{recs, errs}
	}()
	select {
	case r := <-done:
		return r.recs, r.errs
	case <-time.After(d):
		t.Fatalf("scanDirTree(%q) hung > %s (DoS); expected prompt return", root, d)
		return nil, nil
	}
}

// TestScanDirTree_SymlinkJARSkipped: a `*.jar` that is actually a
// symlink must never be followed.  This closes the size-cap bypass —
// the link's own Lstat size is tiny, so the old d.Info() check let it
// past the cap and extractFromJar then followed it to an arbitrarily
// large target.  The target here lives OUTSIDE the scan tree, so the
// only way its identity could surface is via the (forbidden) follow.
func TestScanDirTree_SymlinkJARSkipped(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "real.jar")
	if err := os.WriteFile(target, buildJARBytes(t, map[string][]byte{
		"META-INF/maven/x/real/pom.properties": []byte("groupId=x\nartifactId=real\nversion=1\n"),
	}), 0o644); err != nil {
		t.Fatalf("write target jar: %v", err)
	}

	scanDir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(scanDir, "evil.jar")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	records, _ := scanDirTreeWithin(t, scanDir, 3*time.Second)
	for _, r := range records {
		if r.Name == "x:real" {
			t.Fatalf("symlinked jar was followed; leaked target identity %q (cap-bypass)", r.Name)
		}
	}
}

// TestScanDirTree_FIFONamedJARNoHang: a FIFO named `*.jar` with no
// writer must be skipped, not opened.  A blocking open() on such a
// pipe hangs forever; the scan must return promptly instead.
func TestScanDirTree_FIFONamedJARNoHang(t *testing.T) {
	scanDir := t.TempDir()
	fifo := filepath.Join(scanDir, "pipe.jar")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}

	records, _ := scanDirTreeWithin(t, scanDir, 3*time.Second)
	if len(records) != 0 {
		t.Fatalf("expected 0 records from a FIFO-only tree, got %+v", records)
	}
}

// TestScanDirTree_RealJARStillScanned is the green-path control: after
// the symlink/FIFO hardening, a genuine regular-file jar in the tree is
// still discovered and extracted.
func TestScanDirTree_RealJARStillScanned(t *testing.T) {
	scanDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(scanDir, "good.jar"), buildJARBytes(t, map[string][]byte{
		"META-INF/maven/x/good/pom.properties": []byte("groupId=x\nartifactId=good\nversion=1\n"),
	}), 0o644); err != nil {
		t.Fatalf("write good jar: %v", err)
	}
	records, errs := scanDirTreeWithin(t, scanDir, 3*time.Second)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	found := false
	for _, r := range records {
		if r.Name == "x:good" {
			found = true
		}
	}
	if !found {
		t.Fatalf("real jar was not scanned; got %+v", records)
	}
}

// TestReadJDKVersion_ReleaseSymlinkNoVersion: a `release` file that is
// a symlink must yield no version (safeio refuses the follow) rather
// than being read through — the scan still completes, the JDK just
// carries an empty version.
func TestReadJDKVersion_ReleaseSymlinkNoVersion(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "payload")
	if err := os.WriteFile(target, []byte(`JAVA_VERSION="21.0.3"`+"\n"), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	jdk := t.TempDir()
	if err := os.Symlink(target, filepath.Join(jdk, "release")); err != nil {
		t.Fatalf("symlink release: %v", err)
	}
	if v := readJDKVersion(jdk); v != "" {
		t.Fatalf("symlinked release was followed: got version %q, want \"\"", v)
	}
}

// TestReadJDKVersion_ReleaseFIFONoHang: a `release` file installed as a
// FIFO must not hang the version read; safeio's O_NONBLOCK + regular
// check returns promptly and readJDKVersion reports no version.
func TestReadJDKVersion_ReleaseFIFONoHang(t *testing.T) {
	jdk := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(jdk, "release"), 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}

	done := make(chan string, 1)
	go func() { done <- readJDKVersion(jdk) }()
	select {
	case v := <-done:
		if v != "" {
			t.Fatalf("FIFO release yielded a version %q, want \"\"", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("readJDKVersion hung on a FIFO release file (DoS); expected prompt \"\"")
	}
}
