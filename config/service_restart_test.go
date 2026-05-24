package config

import "testing"

// TestServerSection_RestartUnitLabel verifies the operator can pin the
// systemd unit / launchd label used by the self-update restart path
// directly in agent.conf, instead of relying on env vars that the
// service-spawned process does not see.
func TestServerSection_RestartUnitLabel(t *testing.T) {
	path := writeTempConfig(t, "[server]\nurl = https://example\nsystemd_unit = sentari-agent-custom.service\nlaunchd_label = system/com.example.sentari\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.Server.SystemdUnit != "sentari-agent-custom.service" {
		t.Errorf("SystemdUnit: got %q", cfg.Server.SystemdUnit)
	}
	if cfg.Server.LaunchdLabel != "system/com.example.sentari" {
		t.Errorf("LaunchdLabel: got %q", cfg.Server.LaunchdLabel)
	}
}

func TestServerSection_RestartUnitLabelDefaultsEmpty(t *testing.T) {
	path := writeTempConfig(t, "[server]\nurl = https://example\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.SystemdUnit != "" || cfg.Server.LaunchdLabel != "" {
		t.Errorf("expected empty defaults, got unit=%q label=%q", cfg.Server.SystemdUnit, cfg.Server.LaunchdLabel)
	}
}
