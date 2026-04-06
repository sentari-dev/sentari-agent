// Package config handles parsing of the agent configuration file (agent.conf).
// The config file uses INI-style sections with key = value pairs.
package config

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// AgentConfig holds all agent configuration.
type AgentConfig struct {
	Server  ServerConfig
	Scanner ScannerConfig
	Proxy   ProxyConfig
	Logging LoggingConfig
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
			log.Printf("config: unknown key [%s] %s — ignored", section, key)
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
		default:
			log.Printf("config: unknown key [%s] %s — ignored", section, key)
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
			log.Printf("config: unknown key [%s] %s — ignored", section, key)
		}
	case "logging":
		switch key {
		case "level":
			c.Logging.Level = value
		case "file":
			c.Logging.File = value
		default:
			log.Printf("config: unknown key [%s] %s — ignored", section, key)
		}
	default:
		log.Printf("config: unknown section [%s] — ignored", section)
	}
	return nil
}
