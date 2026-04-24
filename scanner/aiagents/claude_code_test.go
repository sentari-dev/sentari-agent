package aiagents

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanClaudeCode_Agents: files directly under ~/.claude/agents
// become records with name "agent:<basename>" (stripped of .md).
func TestScanClaudeCode_Agents(t *testing.T) {
	tmp := t.TempDir()
	agents := filepath.Join(tmp, "agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	files := []string{"code-reviewer.md", "devops-orchestrator.md", "README.txt", "nested"}
	for _, f := range files {
		p := filepath.Join(agents, f)
		if f == "nested" {
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatalf("mkdir nested: %v", err)
			}
			continue
		}
		if err := os.WriteFile(p, []byte("---\nname: x\n---\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	records, errs := scanClaudeCode(agents)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	names := map[string]bool{}
	for _, r := range records {
		names[r.Name] = true
	}
	if !names["agent:code-reviewer"] {
		t.Errorf("code-reviewer agent not surfaced; got %v", names)
	}
	if !names["agent:devops-orchestrator"] {
		t.Errorf("devops-orchestrator agent not surfaced; got %v", names)
	}
	if names["agent:README"] {
		t.Errorf("non-.md file README.txt leaked as agent")
	}
	if names["agent:nested"] {
		t.Errorf("subdirectory 'nested' leaked as agent")
	}
}

// TestScanClaudeCode_Skills: a skill is a *directory* under
// skills/ with a SKILL.md file inside.  Directories without the
// marker file are skipped.
func TestScanClaudeCode_Skills(t *testing.T) {
	tmp := t.TempDir()
	skills := filepath.Join(tmp, "skills")
	// Valid skill
	sk1 := filepath.Join(skills, "brainstorming")
	if err := os.MkdirAll(sk1, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sk1, "SKILL.md"), []byte("name: brainstorming"), 0o644); err != nil {
		t.Fatalf("write SKILL.md: %v", err)
	}
	// Incomplete skill — no SKILL.md
	sk2 := filepath.Join(skills, "incomplete")
	if err := os.MkdirAll(sk2, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	records, _ := scanClaudeCode(skills)
	names := map[string]bool{}
	for _, r := range records {
		names[r.Name] = true
	}
	if !names["skill:brainstorming"] {
		t.Errorf("valid skill missed: %v", names)
	}
	if names["skill:incomplete"] {
		t.Errorf("directory without SKILL.md should not surface as a skill")
	}
}

// TestScanClaudeCode_Plugins: a plugin is a directory containing
// plugin.json.  No plugin.json = not emitted.
func TestScanClaudeCode_Plugins(t *testing.T) {
	tmp := t.TempDir()
	plugins := filepath.Join(tmp, "plugins")
	p1 := filepath.Join(plugins, "superpowers")
	if err := os.MkdirAll(p1, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(p1, "plugin.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	records, _ := scanClaudeCode(plugins)
	found := false
	for _, r := range records {
		if r.Name == "plugin:superpowers" {
			found = true
		}
	}
	if !found {
		t.Errorf("superpowers plugin missed")
	}
}

// TestDiscoverClaudeCode_NoHome: HOME absent → 0 envs, no panic.
func TestDiscoverClaudeCode_NoHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	envs := discoverClaudeCode()
	if len(envs) != 0 {
		t.Errorf("expected 0 envs with empty HOME; got %v", envs)
	}
}
