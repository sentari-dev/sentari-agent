package runtimeversions

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// findBroker tolerates extra entries (count-agnostic).
func findBroker(got []InstalledRuntime, name string) (InstalledRuntime, bool) {
	for _, r := range got {
		if r.Name == name {
			return r, true
		}
	}
	return InstalledRuntime{}, false
}

func TestDetectRabbitMQFromPkg(t *testing.T) {
	dir := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(dir, "rabbit", "sbin"), 0o755))
	writeFile(t, filepath.Join(dir, "rabbit", "sbin", "rabbitmq-server"), "#!/bin/sh")
	got := DetectAllBrokers(context.Background(), []string{dir},
		func(n string) string {
			if n == "rabbitmq-server" {
				return "3.12.0"
			}
			return ""
		})
	r, ok := findBroker(got, "rabbitmq")
	if !ok || r.Version != "3.12.0" {
		t.Fatalf("expected rabbitmq 3.12.0, got %+v", got)
	}
}

// TestDetectRabbitMQFromPkg_NoDuplicatesAcrossSiblingDirs guards against the
// mass-false-positive regression: pkgVersion("rabbitmq-server") is
// independent of the directory being classified, so folding it into
// classifyBroker's per-directory gate used to fire once per sibling
// directory walked — dozens of bogus "rabbitmq" entries with garbage
// install_paths whenever the OS package was installed. The fix moves the
// package-only case to a single post-walk fallback in DetectAllBrokers.
func TestDetectRabbitMQFromPkg_NoDuplicatesAcrossSiblingDirs(t *testing.T) {
	parent := t.TempDir()
	for _, sub := range []string{"ssl", "apt", "cron.d"} {
		must(t, os.MkdirAll(filepath.Join(parent, sub), 0o755))
	}
	got := DetectAllBrokers(context.Background(), []string{parent},
		func(n string) string {
			if n == "rabbitmq-server" {
				return "3.12.0"
			}
			return ""
		})
	count := 0
	var version string
	for _, r := range got {
		if r.Name == "rabbitmq" {
			count++
			version = r.Version
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 rabbitmq entry, got %d: %+v", count, got)
	}
	if version != "3.12.0" {
		t.Fatalf("expected version 3.12.0, got %q", version)
	}
}

func TestDetectKafkaFromJar(t *testing.T) {
	dir := t.TempDir()
	inst := filepath.Join(dir, "kafka")
	must(t, os.MkdirAll(filepath.Join(inst, "bin"), 0o755))
	must(t, os.MkdirAll(filepath.Join(inst, "libs"), 0o755))
	writeFile(t, filepath.Join(inst, "bin", "kafka-server-start.sh"), "#!/bin/sh")
	writeFile(t, filepath.Join(inst, "libs", "kafka_2.13-3.7.0.jar"), "x")
	got := DetectAllBrokers(context.Background(), []string{dir},
		func(string) string { return "" })
	r, ok := findBroker(got, "kafka")
	if !ok || r.Version != "3.7.0" {
		t.Fatalf("expected kafka 3.7.0, got %+v", got)
	}
}

func TestDetectActiveMQClassicAndArtemis(t *testing.T) {
	dir := t.TempDir()
	classic := filepath.Join(dir, "activemq")
	must(t, os.MkdirAll(filepath.Join(classic, "lib"), 0o755))
	writeFile(t, filepath.Join(classic, "lib", "activemq-broker-5.18.3.jar"), "x")
	artemis := filepath.Join(dir, "artemis")
	must(t, os.MkdirAll(filepath.Join(artemis, "lib"), 0o755))
	writeFile(t, filepath.Join(artemis, "lib", "artemis-server-2.33.0.jar"), "x")
	got := DetectAllBrokers(context.Background(), []string{dir},
		func(string) string { return "" })
	if r, ok := findBroker(got, "activemq"); !ok || r.Version != "5.18.3" {
		t.Fatalf("expected activemq 5.18.3, got %+v", got)
	}
	if r, ok := findBroker(got, "activemq-artemis"); !ok || r.Version != "2.33.0" {
		t.Fatalf("expected activemq-artemis 2.33.0, got %+v", got)
	}
}
