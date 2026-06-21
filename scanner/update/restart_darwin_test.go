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

// A launchd label taken from the environment must be validated against
// a strict allow-list before it is handed to exec on the highest-
// privilege (self-update restart) path.  Labels carrying shell
// metacharacters, whitespace, path traversal, or option-injection
// dashes must be rejected without ever invoking the runner.
func TestRestartService_darwin_rejectsMaliciousLabel(t *testing.T) {
	bad := []string{
		"evil; rm -rf /",
		"label with spaces",
		"system/../../etc/cron.d/x",
		"label$(whoami)",
		"label`id`",
		"label|tee",
		"system/dev.sentari.agent\nkickstart\nother",
		"-malformed",
		"/absolute/path",
		"system//dev.sentari.agent",
		"system/.hidden",
	}
	for _, label := range bad {
		t.Run(label, func(t *testing.T) {
			t.Setenv("SENTARI_AGENT_LAUNCHD_LABEL", label)
			called := false
			prev := cmdRunner
			cmdRunner = func(name string, args ...string) ([]byte, error) {
				called = true
				return nil, nil
			}
			t.Cleanup(func() { cmdRunner = prev })
			err := restartService("/usr/local/bin/sentari-agent")
			if err == nil {
				t.Fatalf("expected rejection for label %q, got nil error", label)
			}
			if called {
				t.Fatalf("runner must not be invoked for rejected label %q", label)
			}
		})
	}
}

func TestRestartService_darwin_acceptsValidLabels(t *testing.T) {
	good := []string{
		"system/dev.sentari.agent",
		"system/com.example.sentari",
		"gui/501/dev.sentari.agent",
		"user/501/com.example.agent",
		"dev.sentari.agent",
		"plain-name",
		"with_underscore.service",
	}
	for _, label := range good {
		t.Run(label, func(t *testing.T) {
			t.Setenv("SENTARI_AGENT_LAUNCHD_LABEL", label)
			c := withStubRunner(t)
			if err := restartService("/usr/local/bin/sentari-agent"); err != nil {
				t.Fatalf("valid label %q rejected: %v", label, err)
			}
			want := []string{"kickstart", "-k", label}
			if !reflect.DeepEqual(c.args, want) {
				t.Fatalf("args mismatch for %q:\n  got:  %v\n  want: %v", label, c.args, want)
			}
		})
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
