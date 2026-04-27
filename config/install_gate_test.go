package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTempConfig drops an INI file in a fresh temp dir and returns
// its path.  Helper for the install-gate parser tests.
func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallGate_DefaultsOff(t *testing.T) {
	path := writeTempConfig(t, "[server]\nurl = https://example\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.InstallGate.Enabled {
		t.Error("InstallGate.Enabled should default to false")
	}
	if cfg.InstallGate.PythonScope != "" {
		t.Errorf("PythonScope: got %q, want empty default", cfg.InstallGate.PythonScope)
	}
}

func TestInstallGate_EnabledTrue(t *testing.T) {
	path := writeTempConfig(t, "[install_gate]\nenabled = true\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InstallGate.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestInstallGate_EnabledBoolFlavours(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"1":     true,
		"yes":   true,
		"on":    true,
		"True":  true, // case-insensitive
		"false": false,
		"0":     false,
		"no":    false,
		"off":   false,
		"":      false,
	}
	for value, want := range cases {
		path := writeTempConfig(t, "[install_gate]\nenabled = "+value+"\n")
		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Errorf("LoadFromFile(%q): %v", value, err)
			continue
		}
		if cfg.InstallGate.Enabled != want {
			t.Errorf("enabled=%q: got %t, want %t", value, cfg.InstallGate.Enabled, want)
		}
	}
}

func TestInstallGate_EnabledRejectsUnknown(t *testing.T) {
	path := writeTempConfig(t, "[install_gate]\nenabled = maybe\n")
	if _, err := LoadFromFile(path); err == nil {
		t.Error("expected error on enabled=maybe")
	}
}

func TestInstallGate_PythonScope(t *testing.T) {
	for _, scope := range []string{"user", "system", ""} {
		path := writeTempConfig(t, "[install_gate]\npython_scope = "+scope+"\n")
		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Errorf("scope=%q: %v", scope, err)
			continue
		}
		if cfg.InstallGate.PythonScope != scope {
			t.Errorf("scope=%q: got %q", scope, cfg.InstallGate.PythonScope)
		}
	}
}

func TestInstallGate_PythonScopeRejectsUnknown(t *testing.T) {
	path := writeTempConfig(t, "[install_gate]\npython_scope = global\n")
	if _, err := LoadFromFile(path); err == nil {
		t.Error("expected error on python_scope=global")
	}
}

func TestInstallGate_NodeScope(t *testing.T) {
	for _, scope := range []string{"user", "system", ""} {
		path := writeTempConfig(t, "[install_gate]\nnode_scope = "+scope+"\n")
		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Errorf("scope=%q: %v", scope, err)
			continue
		}
		if cfg.InstallGate.NodeScope != scope {
			t.Errorf("scope=%q: got %q", scope, cfg.InstallGate.NodeScope)
		}
	}
}

func TestInstallGate_NodeScopeRejectsUnknown(t *testing.T) {
	path := writeTempConfig(t, "[install_gate]\nnode_scope = global\n")
	if _, err := LoadFromFile(path); err == nil {
		t.Error("expected error on node_scope=global")
	}
}

func TestInstallGate_MavenScope(t *testing.T) {
	for _, scope := range []string{"user", "system", ""} {
		path := writeTempConfig(t, "[install_gate]\nmaven_scope = "+scope+"\n")
		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Errorf("scope=%q: %v", scope, err)
			continue
		}
		if cfg.InstallGate.MavenScope != scope {
			t.Errorf("scope=%q: got %q", scope, cfg.InstallGate.MavenScope)
		}
	}
}

func TestInstallGate_MavenScopeRejectsUnknown(t *testing.T) {
	path := writeTempConfig(t, "[install_gate]\nmaven_scope = global\n")
	if _, err := LoadFromFile(path); err == nil {
		t.Error("expected error on maven_scope=global")
	}
}

func TestInstallGate_NuGetScope(t *testing.T) {
	for _, scope := range []string{"user", "system", ""} {
		path := writeTempConfig(t, "[install_gate]\nnuget_scope = "+scope+"\n")
		cfg, err := LoadFromFile(path)
		if err != nil {
			t.Errorf("scope=%q: %v", scope, err)
			continue
		}
		if cfg.InstallGate.NuGetScope != scope {
			t.Errorf("scope=%q: got %q", scope, cfg.InstallGate.NuGetScope)
		}
	}
}

func TestInstallGate_NuGetScopeRejectsUnknown(t *testing.T) {
	path := writeTempConfig(t, "[install_gate]\nnuget_scope = global\n")
	if _, err := LoadFromFile(path); err == nil {
		t.Error("expected error on nuget_scope=global")
	}
}

func TestInstallGate_UnknownKeyIgnored(t *testing.T) {
	// Unknown key under [install_gate] must be a warning, not a
	// load error — operators on a newer INI shouldn't have to
	// downgrade their config when running an older agent build
	// that doesn't recognise a key yet.
	path := writeTempConfig(t, "[install_gate]\nfuture_field = banana\n")
	if _, err := LoadFromFile(path); err != nil {
		t.Errorf("unknown key should not error: %v", err)
	}
}
