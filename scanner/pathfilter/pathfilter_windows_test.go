//go:build windows

package pathfilter

import "testing"

// TestIsCloudSyncedPath_windows exercises the Windows OneDrive branch
// of IsCloudSyncedPath.  Mount points are per-account and exported via
// the OneDrive client's env vars (%OneDrive% / %OneDriveCommercial%),
// with a \Users\<user>\OneDrive* convention fallback for named-tenant
// folders the env vars may not enumerate.  Env-driven so the test is
// hermetic; runs only on windows (the branch is GOOS-gated) but the
// file is compile-checked everywhere via `GOOS=windows go vet`.
func TestIsCloudSyncedPath_windows(t *testing.T) {
	t.Setenv("OneDrive", `C:\Users\alice\OneDrive`)
	t.Setenv("OneDriveCommercial", `C:\Users\alice\OneDrive - Acme`)
	t.Setenv("OneDriveConsumer", "")
	t.Setenv("USERPROFILE", `C:\Users\alice`)

	cases := []struct {
		path string
		want bool
	}{
		// Under the personal OneDrive root (env-derived).
		{`C:\Users\alice\OneDrive\work\.venv`, true},
		// The root itself, exact match.
		{`C:\Users\alice\OneDrive`, true},
		// Under the commercial OneDrive root (env-derived).
		{`C:\Users\alice\OneDrive - Acme\repo\.venv`, true},
		// Named-tenant folder the env vars don't list, caught by the
		// \Users\<user>\OneDrive* convention fallback.
		{`C:\Users\alice\OneDrive - Contoso\code`, true},
		// A sibling that merely starts with the profile but is not
		// OneDrive — must not match.
		{`C:\Users\alice\Documents\repo\.venv`, false},
		// "OneDriveTemp" under the profile begins with "OneDrive" so it
		// matches the prefix convention — acceptable: it is OneDrive
		// scratch state, still worth skipping.
		{`C:\Users\alice\OneDriveTemp\x`, true},
		// A different user's non-OneDrive tree — no env root, not under
		// alice's profile.
		{`C:\Users\bob\Documents\repo`, false},
		// Outside any user profile.
		{`C:\Program Files\Python312\Lib`, false},
		// Relative path and empty input never match.
		{`OneDrive\x`, false},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			if got := IsCloudSyncedPath(c.path); got != c.want {
				t.Fatalf("IsCloudSyncedPath(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}
