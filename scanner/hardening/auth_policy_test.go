package hardening

import (
	"path/filepath"
	"testing"
)

// TestCollectAuthPolicy_Fixture parses login.defs (space-KV), pwquality.conf
// and faillock.conf (equals-KV) from testdata and asserts each mapped value.
func TestCollectAuthPolicy_Fixture(t *testing.T) {
	obs := collectAuthPolicy(
		filepath.Join("testdata", "login.defs"),
		filepath.Join("testdata", "pwquality.conf"),
		filepath.Join("testdata", "faillock.conf"),
	)
	assertValue(t, mustObs(t, obs, "auth_policy.pass_max_days"), "90")
	assertValue(t, mustObs(t, obs, "auth_policy.pass_min_days"), "7")
	assertValue(t, mustObs(t, obs, "auth_policy.pass_min_len"), "14")
	assertValue(t, mustObs(t, obs, "auth_policy.pass_min_class"), "4")
	assertValue(t, mustObs(t, obs, "auth_policy.faillock_deny"), "5")
	assertValue(t, mustObs(t, obs, "auth_policy.faillock_unlock_time"), "900")
}

// TestCollectAuthPolicy_UnreadableSource: an absent source yields unknown for
// only the keys it feeds ("not found"), independently of the other sources.
func TestCollectAuthPolicy_UnreadableSource(t *testing.T) {
	obs := collectAuthPolicy(
		filepath.Join(t.TempDir(), "missing-login.defs"),
		filepath.Join("testdata", "pwquality.conf"),
		filepath.Join("testdata", "faillock.conf"),
	)
	// login.defs missing => its two keys unknown.
	assertUnknown(t, mustObs(t, obs, "auth_policy.pass_max_days"), "not found")
	assertUnknown(t, mustObs(t, obs, "auth_policy.pass_min_days"), "not found")
	// pwquality/faillock still resolve.
	assertValue(t, mustObs(t, obs, "auth_policy.pass_min_len"), "14")
	assertValue(t, mustObs(t, obs, "auth_policy.faillock_deny"), "5")
}

// TestCollectAuthPolicy_KeyNotSet: a readable source missing a specific key
// yields unknown with the "not set" reason (distinct from "not found").
func TestCollectAuthPolicy_KeyNotSet(t *testing.T) {
	dir := t.TempDir()
	// login.defs present but without PASS_MIN_DAYS.
	ld := writeTemp(t, dir, "login.defs", "PASS_MAX_DAYS 42\n")
	pq := writeTemp(t, dir, "pwquality.conf", "minlen = 8\n") // no minclass
	fl := writeTemp(t, dir, "faillock.conf", "deny = 3\n")    // no unlock_time
	obs := collectAuthPolicy(ld, pq, fl)
	assertValue(t, mustObs(t, obs, "auth_policy.pass_max_days"), "42")
	assertUnknown(t, mustObs(t, obs, "auth_policy.pass_min_days"), "not set")
	assertUnknown(t, mustObs(t, obs, "auth_policy.pass_min_class"), "not set")
	assertUnknown(t, mustObs(t, obs, "auth_policy.faillock_unlock_time"), "not set")
}

func TestParseSpaceKV(t *testing.T) {
	m := parseSpaceKV([]byte("# comment\nPASS_MAX_DAYS   90\nUMASK 022\nPASS_MAX_DAYS 5\nlonelykey\n"))
	if m["pass_max_days"] != "90" { // first occurrence wins
		t.Errorf("pass_max_days=%q, want 90 (first wins)", m["pass_max_days"])
	}
	if m["umask"] != "022" {
		t.Errorf("umask=%q", m["umask"])
	}
	if _, ok := m["lonelykey"]; ok {
		t.Error("bare single-field line must be skipped in space-KV")
	}
	if got := parseSpaceKV(nil); len(got) != 0 {
		t.Error("parseSpaceKV(nil) should be empty")
	}
}

func TestParseEqualsKV(t *testing.T) {
	m := parseEqualsKV([]byte("# c\nminlen = 14\nminclass=4\naudit\ndeny = 5\ndeny = 9\n"))
	if m["minlen"] != "14" {
		t.Errorf("minlen=%q", m["minlen"])
	}
	if m["minclass"] != "4" {
		t.Errorf("minclass=%q", m["minclass"])
	}
	if m["audit"] != "true" { // bare key => "true"
		t.Errorf("bare key audit=%q, want true", m["audit"])
	}
	if m["deny"] != "5" { // first wins
		t.Errorf("deny=%q, want 5 (first wins)", m["deny"])
	}
	if got := parseEqualsKV(nil); len(got) != 0 {
		t.Error("parseEqualsKV(nil) should be empty")
	}
}
