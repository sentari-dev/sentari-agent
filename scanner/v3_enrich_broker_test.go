package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestEnrichWithV3_DetectsKafka(t *testing.T) {
	root := t.TempDir()
	inst := filepath.Join(root, "kafka")
	if err := os.MkdirAll(filepath.Join(inst, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(inst, "libs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inst, "bin", "kafka-server-start.sh"), []byte("#!/bin/sh"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inst, "libs", "kafka_2.13-3.7.0.jar"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := &ScanResult{}
	enrichWithV3(context.Background(), result, []string{root}, root)

	found := false
	for _, r := range result.InstalledRuntimes {
		if r.Name == "kafka" && r.Version == "3.7.0" && r.InstallPath == inst {
			found = true
		}
	}
	if !found {
		t.Fatalf("kafka not detected at %s; runtimes=%+v", inst, result.InstalledRuntimes)
	}
}
