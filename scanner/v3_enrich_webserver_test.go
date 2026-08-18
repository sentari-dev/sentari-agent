package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrichWithV3_DetectsNginx(t *testing.T) {
	root := t.TempDir()
	inst := filepath.Join(root, "nginx")
	if err := os.MkdirAll(filepath.Join(inst, "conf"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inst, "conf", "nginx.conf"), []byte("worker_processes 1;"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := &ScanResult{
		Packages: []PackageRecord{
			{Name: "nginx", Version: "1.24.0", EnvType: EnvSystemDeb},
		},
	}
	enrichWithV3(context.Background(), result, []string{root}, root)

	found := false
	for _, r := range result.InstalledRuntimes {
		if r.Name == "nginx" && r.Version == "1.24.0" && r.InstallPath == inst {
			found = true
		}
	}
	if !found {
		t.Fatalf("nginx not detected; runtimes=%+v", result.InstalledRuntimes)
	}
}
