package config

import (
	"reflect"
	"testing"
)

func TestParseAgentTags_BasicCanonicalisation(t *testing.T) {
	got := parseAgentTags("environment:production, team:platform, service:web")
	want := []string{"environment:production", "service:web", "team:platform"} // sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseAgentTags_DedupesAndDropsInvalid(t *testing.T) {
	got := parseAgentTags(
		"environment:production, BAD_KEY:value, team:platform, environment:production",
	)
	want := []string{"environment:production", "team:platform"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseAgentTags_EmptyInputs(t *testing.T) {
	for _, in := range []string{"", "   ", ",,, ,,"} {
		if got := parseAgentTags(in); got != nil {
			t.Errorf("input %q: got %v, want nil", in, got)
		}
	}
}

func TestParseAgentTags_CapAt32(t *testing.T) {
	var b []byte
	for i := 0; i < 50; i++ {
		if i > 0 {
			b = append(b, ',', ' ')
		}
		// keys k01 / k02 / ... — all valid + distinct.
		b = append(b, []byte("key"+itoa2(i)+":v")...)
	}
	got := parseAgentTags(string(b))
	if len(got) != 32 {
		t.Errorf("expected cap at 32, got %d", len(got))
	}
}

func itoa2(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// File-level integration: LoadFromFile populates Agent.Tags.
func TestLoadFromFile_AgentTags(t *testing.T) {
	path := writeTempConfig(t, "[agent]\ntags = env:prod, team:platform\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	want := []string{"env:prod", "team:platform"}
	if !reflect.DeepEqual(cfg.Agent.Tags, want) {
		t.Errorf("Agent.Tags: got %v, want %v", cfg.Agent.Tags, want)
	}
}

func TestLoadFromFile_AgentTagsDefaultEmpty(t *testing.T) {
	path := writeTempConfig(t, "[server]\nurl = https://example\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(cfg.Agent.Tags) != 0 {
		t.Errorf("expected empty default, got %v", cfg.Agent.Tags)
	}
}
