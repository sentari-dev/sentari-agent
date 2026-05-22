//go:build darwin

package update

import (
	"reflect"
	"testing"
)

// captureRunner stubs out the shell-out so the test asserts on the
// exact command line the restart hook would invoke, without spawning
// launchctl.  Defended against the 2026-05-22 regression where the
// hardcoded launchd label silently diverged from the install-time
// plist's ``dev.sentari.agent``.
type captured struct {
	name string
	args []string
}

func withStubRunner(t *testing.T) *captured {
	t.Helper()
	prev := cmdRunner
	c := &captured{}
	cmdRunner = func(name string, args ...string) ([]byte, error) {
		c.name = name
		c.args = append([]string(nil), args...)
		return nil, nil
	}
	t.Cleanup(func() { cmdRunner = prev })
	return c
}

func TestRestartService_darwin_defaultLabel(t *testing.T) {
	t.Setenv("SENTARI_AGENT_LAUNCHD_LABEL", "")
	c := withStubRunner(t)

	if err := restartService("/usr/local/bin/sentari-agent"); err != nil {
		t.Fatalf("restartService failed: %v", err)
	}
	if c.name != "/bin/launchctl" {
		t.Fatalf("expected /bin/launchctl, got %q", c.name)
	}
	want := []string{"kickstart", "-k", defaultDarwinLaunchdLabel}
	if !reflect.DeepEqual(c.args, want) {
		t.Fatalf("args mismatch:\n  got:  %v\n  want: %v", c.args, want)
	}
}

func TestRestartService_darwin_envOverride(t *testing.T) {
	t.Setenv("SENTARI_AGENT_LAUNCHD_LABEL", "system/com.example.sentari")
	c := withStubRunner(t)

	if err := restartService("/usr/local/bin/sentari-agent"); err != nil {
		t.Fatalf("restartService failed: %v", err)
	}
	want := []string{"kickstart", "-k", "system/com.example.sentari"}
	if !reflect.DeepEqual(c.args, want) {
		t.Fatalf("args mismatch:\n  got:  %v\n  want: %v", c.args, want)
	}
}

func TestRestartService_darwin_defaultMatchesShippedPlist(t *testing.T) {
	// The install-time LaunchDaemons plist uses ``dev.sentari.agent``.
	// If anyone changes the default to a different reverse-DNS label,
	// this test fails on purpose so they update the plist too.
	if defaultDarwinLaunchdLabel != "system/dev.sentari.agent" {
		t.Fatalf("default label drifted: got %q; update deploy/macos plist if intentional",
			defaultDarwinLaunchdLabel)
	}
}
