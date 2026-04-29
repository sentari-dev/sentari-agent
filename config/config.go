// Package config handles parsing of the agent configuration file (agent.conf).
// The config file uses INI-style sections with key = value pairs.
package config

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// AgentConfig holds all agent configuration.
type AgentConfig struct {
	Server      ServerConfig
	Scanner     ScannerConfig
	Proxy       ProxyConfig
	Logging     LoggingConfig
	InstallGate InstallGateConfig
}

// ServerConfig holds server connection settings.
type ServerConfig struct {
	URL          string // Sentari server URL
	CertFile     string // Client certificate path
	KeyFile      string // Client key path
	CACertFile   string // Server CA certificate path
	PollInterval int    // Config poll interval in seconds (default: 900)
}

// ScannerConfig holds scanner settings.
type ScannerConfig struct {
	ScanRoot string // Filesystem root to scan (default: / or C:\)
	MaxDepth int    // Max directory depth (default: 8)
	Interval int    // Scan interval in seconds (default: 3600)
	// ScanContainers enables the Sprint-17 container-image scanner
	// (Docker / Podman / CRI-O — containerd deferred).  INI key:
	// ``[scanner] containers = true``.  Also honoured via the
	// ``SENTARI_SCAN_CONTAINERS=true`` env override at main.go.
	// Defaults to false: off-by-default until fleet telemetry
	// validates the performance shape on real hosts.
	ScanContainers bool
}

// ProxyConfig holds forward proxy settings.
type ProxyConfig struct {
	HTTPSProxy       string // Proxy URL
	NoProxy          string // Bypass list (comma-separated)
	AuthUser         string // Proxy auth username
	AuthPassFile     string // Path to file containing proxy password
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Level string // Log level: debug, info, warn, error
	File  string // Log file path (empty = stderr)
}

// InstallGateConfig holds install-gate (preventive enforcement)
// settings.  Phase-B feature; off-by-default until the rollout
// graduates to GA.
//
// INI section:
//
//	[install_gate]
//	enabled = true
//	python_scope = user|system
type InstallGateConfig struct {
	// Enabled gates the entire install-gate feature on the agent.
	// When false (default), the agent does not fetch the
	// policy-map, does not write any native package-manager
	// configs, and emits no install-gate audit events.  Operators
	// pre-stage policies via the dashboard against this dormant
	// flag so the flip-day is a no-op for them.
	Enabled bool

	// PythonScope selects the pip-config target on hosts with
	// Python installed.  ``user`` writes ``~/.config/pip/pip.conf``
	// (laptop default); ``system`` writes ``/etc/pip.conf`` (server
	// default but requires the agent to run as root).  Empty
	// resolves to ``user`` at apply time.
	PythonScope string

	// NodeScope selects the npm-config target on hosts with Node
	// installed.  ``user`` writes ``~/.npmrc``; ``system`` writes
	// ``/etc/npmrc`` (Linux/macOS only — the npm "global" prefix
	// on Windows is install-method-dependent so the npm writer
	// soft-no-ops there for system scope).  Empty resolves to
	// ``user`` at apply time.
	NodeScope string

	// MavenScope selects the Maven settings.xml target on hosts
	// with Maven installed.  ``user`` writes ``~/.m2/settings.xml``;
	// ``system`` writes ``$MAVEN_HOME/conf/settings.xml`` (soft no-op
	// when MAVEN_HOME is unset, since Maven's install path is non-
	// stable across distros).  Empty resolves to ``user`` at apply
	// time.
	MavenScope string

	// NuGetScope selects the NuGet config target on hosts with
	// .NET installed.  ``user`` writes the per-user
	// ``NuGet.Config`` (``%APPDATA%\NuGet\NuGet.Config`` on
	// Windows, ``~/.nuget/NuGet/NuGet.Config`` on POSIX);
	// ``system`` writes a Sentari-Config drop-in under
	// ``%ProgramData%\NuGet\Config\`` (Windows only — POSIX has
	// no system-wide NuGet config dir, the writer soft-no-ops).
	// Empty resolves to ``user`` at apply time.
	NuGetScope string

	// UvScope selects the uv.toml target on hosts with Astral's
	// uv installed.  ``user`` writes the per-user ``uv.toml``;
	// ``system`` writes ``/etc/uv/uv.toml`` (POSIX) or
	// ``%PROGRAMDATA%\uv\uv.toml`` (Windows).  Empty resolves
	// to ``user`` at apply time.
	UvScope string

	// PdmScope selects the pdm config target.  ``user`` writes
	// the per-user pdm config; ``system`` is a soft no-op (pdm
	// has no system-wide config path).  Empty resolves to
	// ``user`` at apply time.
	PdmScope string

	// GradleScope selects the gradle init-script target.
	// ``user`` writes ``~/.gradle/init.d/sentari-proxy.gradle``;
	// ``system`` writes ``$GRADLE_HOME/init.d/sentari-proxy.gradle``
	// (soft no-op when GRADLE_HOME is unset).
	GradleScope string

	// SbtScope selects the sbt repositories-file target.
	// ``user`` writes ``~/.sbt/repositories``; ``system`` writes
	// ``$SBT_HOME/conf/repositories`` (soft no-op when SBT_HOME
	// is unset).
	SbtScope string

	// YarnBerryScope selects the Yarn Berry .yarnrc.yml target.
	// Yarn classic (1.x) reads .npmrc and is covered by the npm
	// writer; this is the separate Berry-specific writer.
	// ``user`` writes ``~/.yarnrc.yml``; ``system`` is a soft
	// no-op (Yarn Berry has no system-wide config path).
	YarnBerryScope string
}

// DefaultConfig returns the default agent configuration.
func DefaultConfig() AgentConfig {
	return AgentConfig{
		Server: ServerConfig{
			PollInterval: 900,
		},
		Scanner: ScannerConfig{
			ScanRoot: "/",
			MaxDepth: 8,
			Interval: 3600,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// LoadFromFile reads and parses an INI-style agent configuration file.
func LoadFromFile(path string) (AgentConfig, error) {
	cfg := DefaultConfig()

	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	section := ""
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}

		// Key = value pair.
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return cfg, fmt.Errorf("line %d: invalid format: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if err := cfg.set(section, key, value); err != nil {
			return cfg, fmt.Errorf("line %d: %w", lineNum, err)
		}
	}

	return cfg, scanner.Err()
}

func (c *AgentConfig) set(section, key, value string) error {
	switch section {
	case "server":
		switch key {
		case "url":
			c.Server.URL = value
		case "cert_file":
			c.Server.CertFile = value
		case "key_file":
			c.Server.KeyFile = value
		case "ca_cert_file":
			c.Server.CACertFile = value
		case "poll_interval":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid poll_interval: %w", err)
			}
			if v <= 0 {
				return fmt.Errorf("poll_interval must be positive, got %d", v)
			}
			c.Server.PollInterval = v
		default:
			slog.Warn("config: unknown key ignored", "section", section, "key", key)
		}
	case "scanner":
		switch key {
		case "scan_root":
			c.Scanner.ScanRoot = value
		case "scan_max_depth":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid scan_max_depth: %w", err)
			}
			if v <= 0 {
				return fmt.Errorf("scan_max_depth must be positive, got %d", v)
			}
			c.Scanner.MaxDepth = v
		case "interval":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid interval: %w", err)
			}
			if v <= 0 {
				return fmt.Errorf("interval must be positive, got %d", v)
			}
			c.Scanner.Interval = v
		case "containers":
			// Accept the usual INI bool flavours so operators
			// don't have to remember which one the parser wants.
			switch strings.ToLower(value) {
			case "true", "1", "yes", "on":
				c.Scanner.ScanContainers = true
			case "false", "0", "no", "off", "":
				c.Scanner.ScanContainers = false
			default:
				return fmt.Errorf("invalid containers value %q (want true/false)", value)
			}
		default:
			slog.Warn("config: unknown key ignored", "section", section, "key", key)
		}
	case "proxy":
		switch key {
		case "https_proxy":
			c.Proxy.HTTPSProxy = value
		case "no_proxy":
			c.Proxy.NoProxy = value
		case "proxy_auth_user":
			c.Proxy.AuthUser = value
		case "proxy_auth_pass_file":
			c.Proxy.AuthPassFile = value
		default:
			slog.Warn("config: unknown key ignored", "section", section, "key", key)
		}
	case "logging":
		switch key {
		case "level":
			c.Logging.Level = value
		case "file":
			c.Logging.File = value
		default:
			slog.Warn("config: unknown key ignored", "section", section, "key", key)
		}
	case "install_gate":
		switch key {
		case "enabled":
			switch strings.ToLower(value) {
			case "true", "1", "yes", "on":
				c.InstallGate.Enabled = true
			case "false", "0", "no", "off", "":
				c.InstallGate.Enabled = false
			default:
				return fmt.Errorf("invalid enabled value %q (want true/false)", value)
			}
		case "python_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.PythonScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid python_scope %q (want user/system)", value)
			}
		case "node_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.NodeScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid node_scope %q (want user/system)", value)
			}
		case "maven_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.MavenScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid maven_scope %q (want user/system)", value)
			}
		case "nuget_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.NuGetScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid nuget_scope %q (want user/system)", value)
			}
		case "uv_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.UvScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid uv_scope %q (want user/system)", value)
			}
		case "pdm_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.PdmScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid pdm_scope %q (want user/system)", value)
			}
		case "gradle_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.GradleScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid gradle_scope %q (want user/system)", value)
			}
		case "sbt_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.SbtScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid sbt_scope %q (want user/system)", value)
			}
		case "yarnberry_scope":
			switch strings.ToLower(value) {
			case "", "user", "system":
				c.InstallGate.YarnBerryScope = strings.ToLower(value)
			default:
				return fmt.Errorf("invalid yarnberry_scope %q (want user/system)", value)
			}
		default:
			slog.Warn("config: unknown key ignored", "section", section, "key", key)
		}
	default:
		slog.Warn("config: unknown section ignored", "section", section)
	}
	return nil
}
