// Package aiagents is the scanner plugin for the "shadow AI" surface
// on a workstation: MCP server configurations, AI-oriented IDE
// extensions, and Claude Code / Codex agent & skill registrations.
//
// Motivation.  As AI agents get more permissions to install software
// and call tools autonomously, the set of things running under a
// developer's identity has expanded beyond what traditional
// package-manager scanners see.  A user who installs five MCP
// servers in Claude Desktop has silently wired five external
// processes — with their own attack surfaces — into their daily
// workflow, but nothing in /var/lib/dpkg or site-packages will
// surface them.  This plugin treats these configurations as
// inventory so fleet operators can ask "which hosts run the
// github-mcp-server?" the same way they ask "which hosts run
// requests 2.31.0?"
//
// Design.  This is a RootScanner plugin: discovery is driven by
// reading fixed well-known config paths (``~/.cursor/mcp.json`` etc.)
// rather than by the shared filesystem walk.  That keeps the
// discovery cost bounded — we never walk entire home directories
// hunting for config, only stat the known paths.
//
// Each AI artefact is emitted as a PackageRecord with
// ``env_type=ai_agent``.  Server-side ecosystem mapping treats
// ai_agent records as a distinct partition so CVE correlation
// doesn't try to join them against PyPI or Maven advisories.
package aiagents

import (
	"context"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// EnvAIAgent is the env_type emitted by every record from this
// plugin.  Mirrors the JVM plugin's EnvJVM convention.
const EnvAIAgent = "ai_agent"

func init() {
	// Register at binary startup like every other plugin.  Agents
	// built WITHOUT this package imported don't ship the scan,
	// which is appropriate — there is no universal "shadow AI"
	// story on a hardened server host.
	scanner.Register(Scanner{})
}

// Scanner implements scanner.RootScanner.  The zero value is
// usable.  Configuration is read from env vars at Scan time, not
// on Scanner construction, because the Sprint-15 context-ID
// correlation expects scanners to be stateless.
type Scanner struct{}

// EnvType reports the env_type this plugin emits on every
// PackageRecord.  Every server-side mapping from env_type to
// ecosystem treats ``ai_agent`` as a distinct bucket.
func (Scanner) EnvType() string { return EnvAIAgent }

// DiscoverAll enumerates every AI-adjacent surface the agent
// knows about on this host.  Surfaces currently covered:
//
//   - MCP server configurations (Claude Desktop, Cursor, Claude
//     Code CLI) — one Environment per config file that exists.
//   - Claude Code agents + skills + plugins directories under
//     ``~/.claude``.
//   - VS Code + Cursor extensions folder, one Environment per
//     install root (each extension inside becomes a record at
//     Scan() time).
//
// Explicitly NOT covered in this first pass:
//
//   - Browser extensions (platform-specific paths; deferred).
//   - "Autonomous install markers" — pip installs attributable
//     to an AI agent via env-var context at install time.
//     Requires instrumenting pip, which Sentari refuses to do
//     (ADR 0003).  A near-equivalent detective rule
//     (install_age combined with a known-AI-agent env-var
//     correlation at scan time) is a follow-up.
func (Scanner) DiscoverAll(ctx context.Context) ([]scanner.Environment, []scanner.ScanError) {
	_ = ctx // reserved for cancellation if discoverers grow heavy
	var envs []scanner.Environment
	envs = append(envs, discoverMCPConfigs()...)
	envs = append(envs, discoverClaudeCode()...)
	envs = append(envs, discoverIDEExtensions()...)
	return envs, nil
}

// Scan dispatches on the Environment's Name (layout tag) to the
// right per-surface walker.  Matches the JVM plugin's dispatch
// pattern — adding a new surface is one constant here + one
// case + one discover function, no changes to the orchestrator.
func (Scanner) Scan(ctx context.Context, env scanner.Environment) ([]scanner.PackageRecord, []scanner.ScanError) {
	_ = ctx
	switch env.Name {
	case layoutMCPConfig:
		return scanMCPConfig(env.Path)
	case layoutClaudeCode:
		return scanClaudeCode(env.Path)
	case layoutIDEExtensions:
		return scanIDEExtensions(env.Path)
	default:
		return nil, nil
	}
}
