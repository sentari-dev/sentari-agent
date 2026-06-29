//go:build linux

package update

import (
	"reflect"
	"testing"
)

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

func TestRestartService_linux_defaultUnit(t *testing.T) {
	t.Setenv("SENTARI_AGENT_SYSTEMD_UNIT", "")
	c := withStubRunner(t)

	if err := restartService("/usr/local/bin/sentari-agent"); err != nil {
		t.Fatalf("restartService failed: %v", err)
	}
	if c.name != "/usr/bin/systemctl" {
		t.Fatalf("expected /usr/bin/systemctl, got %q", c.name)
	}
	want := []string{"restart", defaultLinuxSystemdUnit}
	if !reflect.DeepEqual(c.args, want) {
		t.Fatalf("args mismatch:\n  got:  %v\n  want: %v", c.args, want)
	}
}

func TestRestartService_linux_envOverride(t *testing.T) {
	t.Setenv("SENTARI_AGENT_SYSTEMD_UNIT", "sentari-agent-custom.service")
	c := withStubRunner(t)

	if err := restartService("/usr/local/bin/sentari-agent"); err != nil {
		t.Fatalf("restartService failed: %v", err)
	}
	want := []string{"restart", "sentari-agent-custom.service"}
	if !reflect.DeepEqual(c.args, want) {
		t.Fatalf("args mismatch:\n  got:  %v\n  want: %v", c.args, want)
	}
}

func TestRestartService_linux_defaultMatchesShippedUnit(t *testing.T) {
	if defaultLinuxSystemdUnit != "sentari-agent.service" {
		t.Fatalf("default unit drifted: got %q; update deploy/systemd if intentional",
			defaultLinuxSystemdUnit)
	}
}

// A unit name taken from the environment must be validated against a
// strict allow-list before it is handed to exec on the highest-
// privilege (self-update restart) path.  Names carrying shell
// metacharacters, whitespace, path separators, or option-injection
// dashes must be rejected without ever invoking the runner.
func TestRestartService_linux_rejectsMaliciousUnit(t *testing.T) {
	bad := []string{
		"evil; rm -rf /",
		"unit name with spaces",
		"../../etc/cron.d/x",
		"/absolute/path.service",
		"unit$(whoami).service",
		"unit`id`.service",
		"unit|tee.service",
		"unit\nrestart\nother",
		"--user",
		"-malformed.service",
	}
	for _, unit := range bad {
		t.Run(unit, func(t *testing.T) {
			t.Setenv("SENTARI_AGENT_SYSTEMD_UNIT", unit)
			c := withStubRunner(t)
			called := false
			cmdRunner = func(name string, args ...string) ([]byte, error) {
				called = true
				return nil, nil
			}
			err := restartService("/usr/local/bin/sentari-agent")
			if err == nil {
				t.Fatalf("expected rejection for unit %q, got nil error", unit)
			}
			if called {
				t.Fatalf("runner must not be invoked for rejected unit %q", unit)
			}
			_ = c
		})
	}
}

func TestRestartService_linux_acceptsValidUnitNames(t *testing.T) {
	good := []string{
		"sentari-agent.service",
		"sentari-agent-custom.service",
		"sentari_agent.service",
		"my.app@instance.service",
		"plain-name",
	}
	for _, unit := range good {
		t.Run(unit, func(t *testing.T) {
			t.Setenv("SENTARI_AGENT_SYSTEMD_UNIT", unit)
			c := withStubRunner(t)
			if err := restartService("/usr/local/bin/sentari-agent"); err != nil {
				t.Fatalf("valid unit %q rejected: %v", unit, err)
			}
			want := []string{"restart", unit}
			if !reflect.DeepEqual(c.args, want) {
				t.Fatalf("args mismatch for %q:\n  got:  %v\n  want: %v", unit, c.args, want)
			}
		})
	}
}
