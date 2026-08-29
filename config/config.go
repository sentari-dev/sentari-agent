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
	Agent       AgentSection
	Cache       CacheConfig
	Audit       AuditConfig
	Hardening   HardeningConfig
}

// HardeningConfig holds the v4 hardening-posture collector settings.
//
// INI section:
//
//	[hardening]
//	enabled = true
//
// Off by default (install-gate-style dormant opt-in): when disabled the agent
// runs no hardening collectors and emits no `hardening_observations` block nor
// the v4 payload header, keeping a default agent's wire shape byte-identical to
// a v3 agent. Operators flip this on once the fleet catalog is staged.
type HardeningConfig struct {
	// Enabled gates the entire hardening-posture feature on the agent.
	Enabled bool
}

// CacheConfig holds local scan-queue (offline cache) settings.
//
// INI section:
//
//	[cache]
//	max_pending_scans = 500
//	max_pending_bytes = 536870912
type CacheConfig struct {
	// MaxPendingScans caps how many not-yet-uploaded scan rows the local
	// SQLite queue retains before EnqueueScan evicts the oldest ones.  It
	// bounds on-disk growth during a server outage or air-gap window: at the
	// default hourly cadence, 500 rows is ~3 weeks of offline operation.  A
	// durably air-gapped fleet on the 365-day tier can raise this (at the cost
	// of disk) so a longer offline burst is retained rather than evicted.
	// Must be non-negative; 0 disables retention (every enqueue evicts older
	// pending rows).  Defaults to cache.DefaultMaxPendingScans (500) and is
	// applied via cache.SetMaxPendingScans at startup.  INI key:
	// `[cache] max_pending_scans`.
	MaxPendingScans int

	// MaxPendingBytes caps the total size (in bytes) of retained
	// not-yet-uploaded scan_json the local SQLite queue holds before
	// EnqueueScan evicts the oldest rows.  It bounds on-disk growth when a
	// few very large scans would otherwise blow past a sensible disk budget
	// even while the row count stays under MaxPendingScans.  Must be
	// non-negative; 0 disables the byte cap (retention is then bounded only
	// by MaxPendingScans).  Defaults to cache.DefaultMaxPendingBytes (512
	// MiB) and is applied via cache.SetMaxPendingBytes at startup.  INI key:
	// `[cache] max_pending_bytes`.
	MaxPendingBytes int
}

// AuditConfig holds local append-only audit-log retention settings.
//
// INI section:
//
//	[audit]
//	max_audit_bytes = 268435456
type AuditConfig struct {
	// MaxAuditBytes is the soft cap, in bytes, on the total logical size of the
	// local append-only audit_log table.  It bounds on-disk growth of the audit
	// log so a long-lived agent does not accumulate audit rows forever: once the
	// estimated table size exceeds this cap, the OLDEST already-SHIPPED rows
	// (server-witnessed, safe to reclaim) are purged oldest-first, always
	// retaining a forensic tail.  UNSHIPPED rows are NEVER purged — on a long
	// air-gap window (up to the 365-day tier) every row is unshipped and the log
	// grows unbounded by design, because that growth is undelivered audit
	// evidence that must be preserved, not discarded.  The cap therefore only
	// ever reclaims history the server has already re-anchored.
	//
	// Must be non-negative; 0 DISABLES the cap (retain every row forever — the
	// audit package's own historical default).  Defaults to
	// DefaultMaxAuditBytes (256 MiB): a generous but real ceiling sized for
	// compliance audit trails on air-gap deployments — audit rows are small (a few
	// hundred bytes each), so 256 MiB is on the order of a million shipped
	// events of reclaimable forensic tail, while still bounding an always-online
	// agent's shipped-and-re-anchored history.  Applied via
	// audit.SetMaxAuditBytes at startup.  INI key: `[audit] max_audit_bytes`.
	MaxAuditBytes int64
}

// DefaultMaxAuditBytes is the built-in bounded cap wired into the audit log's
// MaxAuditBytes retention knob when the operator does not set `[audit]
// max_audit_bytes`.  256 MiB.  Kept as a package literal (like the cache
// defaults) so this leaf config package does not import the audit package; the
// audit package's own MaxAuditBytes var still defaults to 0 (disabled) for
// callers that do not wire this in, and this default is what the enterprise
// agent applies at startup to make the log bounded out of the box.
const DefaultMaxAuditBytes int64 = 256 << 20 // 256 MiB

// AgentSection holds operator-supplied per-host metadata that the
// agent emits on every scan upload.  The server filters against
// these tags on the dashboard side.
//
// INI section:
//
//	[agent]
//	tags = environment:production, team:platform, service:web
//
// Each entry must match the same regex the server enforces:
//
//	^[a-z][a-z0-9_-]{0,63}:[A-Za-z0-9._-]{1,128}$
//
// Invalid entries are logged + dropped — don't block agent startup
// on a single typo.  Cap at 32 entries (parser truncates with a
// warning if more).
//
// `Tags` is a *pointer* to a slice so we can distinguish three
// states on the wire:
//
//	nil          → `[agent]` section absent OR no `tags` key →
//	               omit the field on /scan → server leaves
//	               `device.tags_agent` untouched (back-compat).
//	&[]string{}  → operator wrote `tags =` with no values →
//	               serialise as `"tags": []` → server clears
//	               `device.tags_agent`.
//	&[]string{…} → populated → server applies the canonical list.
type AgentSection struct {
	Tags *[]string
}

// ServerConfig holds server connection settings.
type ServerConfig struct {
	URL          string // Sentari server URL
	CertFile     string // Client certificate path
	KeyFile      string // Client key path
	CACertFile   string // Server CA certificate path
	PollInterval int    // Config poll interval in seconds (default: 900)

	// SystemdUnit / LaunchdLabel let an operator pin the service
	// identity the self-update restart path bounces, for installs that
	// don't use the shipped defaults.  These exist because the restart
	// step previously honoured only the SENTARI_AGENT_SYSTEMD_UNIT /
	// SENTARI_AGENT_LAUNCHD_LABEL env vars — which the service-spawned
	// agent process does not inherit.  Empty means "use the built-in
	// default".  INI keys: `[server] systemd_unit` / `launchd_label`.
	SystemdUnit  string // e.g. sentari-agent.service (Linux)
	LaunchdLabel string // e.g. system/dev.sentari.agent (macOS)
}

// ScannerConfig holds scanner settings.
type ScannerConfig struct {
	ScanRoot string // Filesystem root to scan (empty = platform default resolved by scanner.NewRunner: / on POSIX, C:\ on Windows)
	MaxDepth int    // Max directory depth (default: 8)
	Interval int    // Scan interval in seconds (default: 3600)
	// ScanContainers enables the Sprint-17 container-image scanner
	// (Docker / Podman / CRI-O — containerd deferred).  INI key:
	// `[scanner] containers = true`.  Also honoured via the
	// `SENTARI_SCAN_CONTAINERS=true` env override at main.go.
	// Defaults to false: off-by-default until fleet telemetry
	// validates the performance shape on real hosts.
	ScanContainers bool
}

// ProxyConfig holds forward proxy settings.
type ProxyConfig struct {
	HTTPSProxy   string // Proxy URL
	NoProxy      string // Bypass list (comma-separated)
	AuthUser     string // Proxy auth username
	AuthPassFile string // Path to file containing proxy password
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
	// Python installed.  `user` writes `~/.config/pip/pip.conf`
	// (laptop default); `system` writes `/etc/pip.conf` (server
	// default but requires the agent to run as root).  Empty
	// resolves to `user` at apply time.
	PythonScope string

	// NodeScope selects the npm-config target on hosts with Node
	// installed.  `user` writes `~/.npmrc`; `system` writes
	// `/etc/npmrc` (Linux/macOS only — the npm "global" prefix
	// on Windows is install-method-dependent so the npm writer
	// soft-no-ops there for system scope).  Empty resolves to
	// `user` at apply time.
	NodeScope string

	// MavenScope selects the Maven settings.xml target on hosts
	// with Maven installed.  `user` writes `~/.m2/settings.xml`;
	// `system` writes `$MAVEN_HOME/conf/settings.xml` (soft no-op
	// when MAVEN_HOME is unset, since Maven's install path is non-
	// stable across distros).  Empty resolves to `user` at apply
	// time.
	MavenScope string

	// NuGetScope selects the NuGet config target on hosts with
	// .NET installed.  `user` writes the per-user
	// `NuGet.Config` (`%APPDATA%\NuGet\NuGet.Config` on
	// Windows, `~/.nuget/NuGet/NuGet.Config` on POSIX);
	// `system` writes a Sentari-Config drop-in under
	// `%ProgramData%\NuGet\Config\` (Windows only — POSIX has
	// no system-wide NuGet config dir, the writer soft-no-ops).
	// Empty resolves to `user` at apply time.
	NuGetScope string

	// UvScope selects the uv.toml target on hosts with Astral's
	// uv installed.  `user` writes the per-user `uv.toml`;
	// `system` writes `/etc/uv/uv.toml` (POSIX) or
	// `%PROGRAMDATA%\uv\uv.toml` (Windows).  Empty resolves
	// to `user` at apply time.
	UvScope string

	// PdmScope selects the pdm config target.  `user` writes
	// the per-user pdm config; `system` is a soft no-op (pdm
	// has no system-wide config path).  Empty resolves to
	// `user` at apply time.
	PdmScope string

	// GradleScope selects the gradle init-script target.
	// `user` writes `~/.gradle/init.d/sentari-proxy.gradle`;
	// `system` writes `$GRADLE_HOME/init.d/sentari-proxy.gradle`
	// (soft no-op when GRADLE_HOME is unset).
	GradleScope string

	// SbtScope selects the sbt repositories-file target.
	// `user` writes `~/.sbt/repositories`; `system` writes
	// `$SBT_HOME/conf/repositories` (soft no-op when SBT_HOME
	// is unset).
	SbtScope string

	// YarnBerryScope selects the Yarn Berry .yarnrc.yml target.
	// Yarn classic (1.x) reads .npmrc and is covered by the npm
	// writer; this is the separate Berry-specific writer.
	// `user` writes `~/.yarnrc.yml`; `system` is a soft
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
			// ScanRoot is intentionally left empty so the
			// platform default resolves at scan time in
			// scanner.NewRunner (/ on POSIX, C:\ on Windows).
			// Hardcoding "/" here defeated the Windows fallback
			// on config-less runs.
			MaxDepth: 8,
			Interval: 3600,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
		Cache: CacheConfig{
			// Mirror cache.DefaultMaxPendingScans (500).  Kept as a literal
			// (like MaxDepth/Interval above) so this leaf config package does
			// not depend on the cache package; the two defaults must stay in
			// sync.
			MaxPendingScans: 500,
			// Mirror cache.DefaultMaxPendingBytes (512 MiB = 512 << 20).  Kept
			// as a literal for the same reason; the two defaults must stay in
			// sync.
			MaxPendingBytes: 512 << 20,
		},
		Audit: AuditConfig{
			// Bound the audit log out of the box (DefaultMaxAuditBytes, 256
			// MiB).  Unlike audit.MaxAuditBytes (which defaults to 0 =
			// disabled for callers that do not wire it), a config-less
			// enterprise agent applies this bounded default via
			// audit.SetMaxAuditBytes so the log cannot grow forever.  0 in the
			// config disables the cap.
			MaxAuditBytes: DefaultMaxAuditBytes,
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

		// Strip a leading UTF-8 BOM (U+FEFF) on the first line.  Windows
		// PowerShell 5.1's Set-Content -Encoding UTF8 prepends one; it is not
		// Unicode whitespace, so the TrimSpace above leaves it in place.
		if lineNum == 1 {
			line = strings.TrimPrefix(line, "\ufeff")
		}

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
		case "systemd_unit":
			c.Server.SystemdUnit = value
		case "launchd_label":
			c.Server.LaunchdLabel = value
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
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
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
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
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
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
		}
	case "logging":
		switch key {
		case "level":
			c.Logging.Level = value
		case "file":
			c.Logging.File = value
		default:
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
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
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
		}
	case "cache":
		switch key {
		case "max_pending_scans":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid max_pending_scans: %w", err)
			}
			if v < 0 {
				return fmt.Errorf("max_pending_scans must be non-negative, got %d", v)
			}
			c.Cache.MaxPendingScans = v
		case "max_pending_bytes":
			v, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid max_pending_bytes: %w", err)
			}
			if v < 0 {
				return fmt.Errorf("max_pending_bytes must be non-negative, got %d", v)
			}
			c.Cache.MaxPendingBytes = v
		default:
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
		}
	case "audit":
		switch key {
		case "max_audit_bytes":
			// int64: the audit retention cap can legitimately exceed 2 GiB on a
			// 32-bit build, and audit.MaxAuditBytes is int64, so parse the full
			// width rather than truncating through int.
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid max_audit_bytes: %w", err)
			}
			if v < 0 {
				return fmt.Errorf("max_audit_bytes must be non-negative, got %d", v)
			}
			c.Audit.MaxAuditBytes = v
		default:
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
		}
	case "hardening":
		switch key {
		case "enabled":
			switch strings.ToLower(value) {
			case "true", "1", "yes", "on":
				c.Hardening.Enabled = true
			case "false", "0", "no", "off", "":
				c.Hardening.Enabled = false
			default:
				return fmt.Errorf("invalid enabled value %q (want true/false)", value)
			}
		default:
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
		}
	case "agent":
		switch key {
		case "tags":
			c.Agent.Tags = parseAgentTags(value)
		default:
			slog.Warn("config: unknown key ignored", slog.String("section", section), slog.String("key", key))
		}
	default:
		slog.Warn("config: unknown section ignored", slog.String("section", section))
	}
	return nil
}
