package runtimeversions

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

var (
	_kafkaJarRE   = regexp.MustCompile(`kafka_[\d.]+-([\d.]+)\.jar`)
	_amqClassicRE = regexp.MustCompile(`activemq-broker-([\d.]+)\.jar`)
	_amqArtemisRE = regexp.MustCompile(`artemis-server-([\d.]+)\.jar`)
	_rabbitDirRE  = regexp.MustCompile(`rabbitmq_server-([\d.]+)`)
)

// DetectAllBrokers walks each parent one level deep and classifies message
// brokers by marker files. pkgVersion supplies an OS-package version (already
// epoch-stripped by the caller) when available. Never executes a binary.
func DetectAllBrokers(ctx context.Context, parents []string, pkgVersion func(name string) string) []InstalledRuntime {
	seen := map[string]struct{}{}
	var out []InstalledRuntime
	consider := func(dir string) {
		clean := filepath.Clean(dir)
		if _, dup := seen[clean]; dup {
			return
		}
		if rt, ok := classifyBroker(clean, pkgVersion); ok {
			seen[clean] = struct{}{}
			out = append(out, rt)
		}
	}
	for _, parent := range parents {
		if ctx.Err() != nil {
			return out
		}
		entries, err := safeio.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, d := range entries {
			if d.IsDir() {
				consider(filepath.Join(parent, d.Name()))
			}
		}
	}
	return out
}

func classifyBroker(dir string, pkgVersion func(name string) string) (InstalledRuntime, bool) {
	// Artemis before Classic (an Artemis tree may ship activemq-* client jars).
	if v := firstJarVersion(filepath.Join(dir, "lib"), _amqArtemisRE); v != "" ||
		isFile(filepath.Join(dir, "bin", "artemis")) {
		return mk("activemq-artemis", v, "Apache ActiveMQ Artemis", dir), true
	}
	if v := firstJarVersion(filepath.Join(dir, "lib"), _amqClassicRE); v != "" ||
		isFile(filepath.Join(dir, "bin", "activemq")) {
		return mk("activemq", v, "Apache ActiveMQ", dir), true
	}
	if isFile(filepath.Join(dir, "bin", "kafka-server-start.sh")) ||
		isFile(filepath.Join(dir, "bin", "kafka-server-start.bat")) {
		v := firstJarVersion(filepath.Join(dir, "libs"), _kafkaJarRE)
		return mk("kafka", v, "Apache", dir), true
	}
	// RabbitMQ: OS package, sbin layout, or a versioned rabbitmq_server-<ver> dir.
	if isFile(filepath.Join(dir, "sbin", "rabbitmq-server")) ||
		pkgVersion("rabbitmq-server") != "" ||
		_rabbitDirRE.MatchString(filepath.Base(dir)) {
		v := pkgVersion("rabbitmq-server")
		if v == "" {
			if m := _rabbitDirRE.FindStringSubmatch(filepath.Base(dir)); m != nil {
				v = m[1]
			}
		}
		return mk("rabbitmq", v, "RabbitMQ", dir), true
	}
	return InstalledRuntime{}, false
}

// firstJarVersion returns the version captured from the first file in libDir
// whose name matches re (reads filenames only — no file contents, no execution).
func firstJarVersion(libDir string, re *regexp.Regexp) string {
	entries, err := safeio.ReadDir(libDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if m := re.FindStringSubmatch(e.Name()); m != nil {
			return strings.TrimRight(m[1], ".")
		}
	}
	return ""
}
