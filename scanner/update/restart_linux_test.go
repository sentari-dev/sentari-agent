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
