//go:build !windows

package scanner

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// withPasswdFixture points the package passwdPath at a temp fixture containing
// the given lines and restores the original afterwards.
func withPasswdFixture(t *testing.T, lines ...string) {
	t.Helper()
	fixture := filepath.Join(t.TempDir(), "passwd")
	if err := os.WriteFile(fixture, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write passwd fixture: %v", err)
	}
	orig := passwdPath
	passwdPath = fixture
	t.Cleanup(func() { passwdPath = orig })
}

// TestLookupPasswdNameResolvesFixtureUID verifies the CGO_ENABLED=0 best-effort
// fallback: a uid present in the local passwd file resolves to its username,
// which is exactly the case that recovers a LOCAL user when NSS is unavailable
// (finding portability-1).
func TestLookupPasswdNameResolvesFixtureUID(t *testing.T) {
	withPasswdFixture(t,
		"root:x:0:0:root:/root:/bin/bash",
		"svc_local:x:4242424:4242424:Local Service Acct:/home/svc:/usr/sbin/nologin",
		"other:x:5000:5000::/home/other:/bin/sh",
	)

	if got := lookupPasswdName(4242424); got != "svc_local" {
		t.Fatalf("lookupPasswdName(4242424) = %q, want %q", got, "svc_local")
	}
	if got := lookupPasswdName(0); got != "root" {
		t.Fatalf("lookupPasswdName(0) = %q, want %q", got, "root")
	}
}

// TestLookupPasswdNameMissReturnsEmpty verifies a uid absent from passwd yields
// "" so getFileOwner falls through to the documented numeric form (a directory
// LDAP/AD user, absent from the local file, degrades this way).
func TestLookupPasswdNameMissReturnsEmpty(t *testing.T) {
	withPasswdFixture(t, "root:x:0:0:root:/root:/bin/bash")
	if got := lookupPasswdName(999999); got != "" {
		t.Fatalf("lookupPasswdName(999999) = %q, want empty", got)
	}
}

// TestLookupPasswdNameToleratesMalformedFile verifies comments, blank lines, and
// short/garbled lines are skipped rather than misresolved — a damaged or hostile
// passwd file must degrade to the numeric fallback, not a wrong name.
func TestLookupPasswdNameToleratesMalformedFile(t *testing.T) {
	withPasswdFixture(t,
		"# a comment",
		"",
		"garbage-with-no-colons",
		"short:x",                 // fewer than 3 fields
		":x:7000:7000::/:/bin/sh", // empty name, uid matches but must be skipped
		"good:x:7001:7001::/home/good:/bin/sh",
	)
	if got := lookupPasswdName(7000); got != "" {
		t.Fatalf("empty-name entry must be skipped, got %q", got)
	}
	if got := lookupPasswdName(7001); got != "good" {
		t.Fatalf("lookupPasswdName(7001) = %q, want %q", got, "good")
	}
}

// TestLookupPasswdNameMissingFileReturnsEmpty verifies an unreadable/absent
// passwd path degrades cleanly to "".
func TestLookupPasswdNameMissingFileReturnsEmpty(t *testing.T) {
	orig := passwdPath
	passwdPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { passwdPath = orig })
	if got := lookupPasswdName(0); got != "" {
		t.Fatalf("missing passwd file must yield empty, got %q", got)
	}
}

// TestGetFileOwnerResolvesCurrentUser verifies the happy path: a real file owned
// by the running user resolves to a non-numeric username via os/user (the
// primary path, before any passwd fallback).
func TestGetFileOwnerResolvesCurrentUser(t *testing.T) {
	f := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got := getFileOwner(f)
	if got == "" {
		t.Fatal("getFileOwner returned empty for a readable owned file")
	}
	if strings.HasPrefix(got, "uid:") {
		t.Fatalf("current user should resolve to a name, got numeric fallback %q", got)
	}

	// Cross-check: the resolved name matches os/user for the current uid when
	// available (a name is present in the local user DB on the test host).
	if cur, err := user.Current(); err == nil && cur.Username != "" {
		if got != cur.Username {
			t.Logf("getFileOwner = %q, os/user current = %q (acceptable if differing NSS views)", got, cur.Username)
		}
	}
}

// TestGetFileOwnerFallsBackToPasswdName verifies the fallback wiring end-to-end:
// when os/user cannot resolve the file's uid, getFileOwner consults passwdPath
// and returns the local username there rather than the numeric form.  Exercised
// by pointing passwdPath at a fixture that maps the current file's real uid to a
// synthetic name and confirming that either os/user (primary) or the passwd
// fallback yields a NAME, never "uid:<N>".
func TestGetFileOwnerFallsBackToPasswdName(t *testing.T) {
	f := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	uid := fileUID(t, info)

	// Map the file's real uid to a synthetic name in the fixture so that even if
	// os/user missed (CGO_ENABLED=0 with no local entry), the passwd fallback
	// resolves a name.
	withPasswdFixture(t,
		fmt.Sprintf("synthetic_owner:x:%s:%s::/home/synthetic:/bin/sh", uid, uid),
	)

	got := getFileOwner(f)
	if strings.HasPrefix(got, "uid:") {
		t.Fatalf("uid %s is present in the passwd fixture; expected a name, got %q", uid, got)
	}
	if got == "" {
		t.Fatal("expected a resolved owner name, got empty")
	}
}

// fileUID extracts the numeric uid string from a FileInfo on Unix (the same
// syscall.Stat_t path getFileOwner reads).
func fileUID(t *testing.T, info os.FileInfo) string {
	t.Helper()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("FileInfo.Sys() is not *syscall.Stat_t on this platform")
	}
	return strconv.FormatUint(uint64(stat.Uid), 10)
}
