package hardening

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// --- shared test helpers (package-internal) --------------------------------

// findObs returns the first observation with the given key, or nil.
func findObs(obs []Observation, key string) *Observation {
	for i := range obs {
		if obs[i].Key == key {
			return &obs[i]
		}
	}
	return nil
}

// mustObs fails the test if the key is absent.
func mustObs(t *testing.T, obs []Observation, key string) Observation {
	t.Helper()
	o := findObs(obs, key)
	if o == nil {
		t.Fatalf("observation %q not emitted; got keys %v", key, keysOf(obs))
	}
	return *o
}

func keysOf(obs []Observation) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.Key)
	}
	return out
}

// writeTemp writes content to dir/name (creating parent dirs) and returns the path.
func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// assertValue asserts a fact observation: non-nil value equal to want, no error.
func assertValue(t *testing.T, o Observation, want string) {
	t.Helper()
	if o.Error != nil {
		t.Fatalf("%s: unexpected error %q (wanted value %q)", o.Key, *o.Error, want)
	}
	if o.Value == nil {
		t.Fatalf("%s: value is nil (wanted %q)", o.Key, want)
	}
	if *o.Value != want {
		t.Fatalf("%s: value=%q, want %q", o.Key, *o.Value, want)
	}
}

// assertUnknown asserts an unreadable/conditional observation: nil value + error
// (optionally containing wantReason). The server scores these `unknown`.
func assertUnknown(t *testing.T, o Observation, wantReason string) {
	t.Helper()
	if o.Value != nil {
		t.Fatalf("%s: expected nil value (unknown), got %q", o.Key, *o.Value)
	}
	if o.Error == nil {
		t.Fatalf("%s: expected error (unknown), got none", o.Key)
	}
	if wantReason != "" && *o.Error != wantReason {
		t.Fatalf("%s: error=%q, want %q", o.Key, *o.Error, wantReason)
	}
}

// --- toggle gating ----------------------------------------------------------

// TestCollect_DisabledEmitsNothing pins the dormant-by-default posture: with the
// [hardening] toggle off, Collect returns nil so the agent emits no v4
// hardening_observations block and byte-identical v3 payloads.
func TestCollect_DisabledEmitsNothing(t *testing.T) {
	if got := Collect(context.Background(), false); got != nil {
		t.Fatalf("Collect(enabled=false) = %v, want nil (feature must be dormant)", got)
	}
}

// TestCollect_EnabledEmits confirms the toggle-on path runs the platform
// collectors and returns a (non-nil) observation set within the payload cap.
func TestCollect_EnabledEmits(t *testing.T) {
	got := Collect(context.Background(), true)
	if got == nil {
		t.Fatal("Collect(enabled=true) returned nil; expected platform observations")
	}
	if len(got) > maxObservations {
		t.Fatalf("Collect returned %d observations, exceeds cap %d", len(got), maxObservations)
	}
}

// --- provenance / observation builders --------------------------------------

func TestSHA256Hex(t *testing.T) {
	// Known vector: sha256("") .
	if got := sha256Hex([]byte("")); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("sha256Hex(empty) = %s", got)
	}
	// abc
	if got := sha256Hex([]byte("abc")); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("sha256Hex(abc) = %s", got)
	}
}

func TestObsBuilders(t *testing.T) {
	// obsValue: real value + provenance, no default_assumed, no error.
	v := obsValue("ssh.protocol", familySSH, "2", "/etc/ssh/sshd_config", "deadbeef")
	assertValue(t, v, "2")
	if v.DefaultAssumed {
		t.Error("obsValue set default_assumed")
	}
	if v.SourcePath == nil || *v.SourcePath != "/etc/ssh/sshd_config" {
		t.Error("obsValue missing source_path")
	}
	if v.SourceSHA256 == nil || *v.SourceSHA256 != "deadbeef" {
		t.Error("obsValue missing source_sha256")
	}
	// empty sha => SourceSHA256 omitted.
	if v2 := obsValue("k", "f", "x", "/p", ""); v2.SourceSHA256 != nil {
		t.Error("obsValue with empty sha must omit source_sha256")
	}

	// obsDefault: default_assumed=true.
	d := obsDefault("ssh.macs", familySSH, "(default)", "/etc/ssh/sshd_config", "abc")
	if !d.DefaultAssumed {
		t.Error("obsDefault must set default_assumed=true")
	}
	assertValue(t, d, "(default)")

	// obsError: null value + reason; source_path preserved when non-empty.
	e := obsError("ssh.ciphers", familySSH, "/etc/ssh/sshd_config", "conditional (Match block)")
	assertUnknown(t, e, "conditional (Match block)")
	if e.SourcePath == nil {
		t.Error("obsError dropped non-empty source_path")
	}
	// empty source path => SourcePath omitted.
	if e2 := obsError("k", "f", "", "boom"); e2.SourcePath != nil {
		t.Error("obsError with empty path must omit source_path")
	}
}

// --- readSource / error classification --------------------------------------

func TestReadSource_OK(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "cfg", "hello")
	data, sha, reason := readSource(p, maxConfigFileSize)
	if reason != "" {
		t.Fatalf("readSource reason=%q, want none", reason)
	}
	if string(data) != "hello" {
		t.Fatalf("readSource data=%q", data)
	}
	if sha != sha256Hex([]byte("hello")) {
		t.Fatalf("readSource sha mismatch: %s", sha)
	}
}

func TestReadSource_NotFound(t *testing.T) {
	_, _, reason := readSource(filepath.Join(t.TempDir(), "nope"), maxConfigFileSize)
	if reason != "not found" {
		t.Fatalf("readSource(missing) reason=%q, want %q", reason, "not found")
	}
}

func TestClassifyReadErr(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{os.ErrNotExist, "not found"},
		{fs.ErrNotExist, "not found"},
		{os.ErrPermission, "permission denied"},
		{errors.New("some other io failure"), "unreadable"},
	}
	for _, c := range cases {
		if got := classifyReadErr(c.err); got != c.want {
			t.Errorf("classifyReadErr(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// TestGuard_RecoversPanic confirms one panicking collector cannot abort the
// pass AND that the panic degrades to explicit `unknown` observations for the
// family (never silent nil, which the server would read as not_applicable).
func TestGuard_RecoversPanic(t *testing.T) {
	got := guard(familyFirewall, func() []Observation { panic("collector exploded") })
	if len(got) != 1 {
		t.Fatalf("panic should emit the family's unknown keys, got %v", got)
	}
	assertUnknown(t, got[0], "collector panicked")
	if got[0].Key != familyFirewall+".enabled" {
		t.Fatalf("panic obs key = %q", got[0].Key)
	}

	// A multi-key family emits an unknown per key.
	sl := guard(familyScreenLock, func() []Observation { panic("boom") })
	if len(sl) != 2 {
		t.Fatalf("screen_lock panic should emit 2 unknowns, got %d", len(sl))
	}

	// Non-panicking collector passes its output through unchanged.
	want := []Observation{{Key: "k", Family: "f"}}
	if got := guard(familyFirewall, func() []Observation { return want }); len(got) != 1 || got[0].Key != "k" {
		t.Fatalf("guard mangled non-panic output: %v", got)
	}
}
