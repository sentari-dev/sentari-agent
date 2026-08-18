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
