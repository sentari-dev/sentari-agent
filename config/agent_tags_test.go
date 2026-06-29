package config

import (
	"reflect"
	"testing"
)

func TestParseAgentTags_BasicCanonicalisation(t *testing.T) {
	got := parseAgentTags("environment:production, team:platform, service:web")
	want := []string{"environment:production", "service:web", "team:platform"} // sorted
	if got == nil || !reflect.DeepEqual(*got, want) {
		t.Errorf("got %v, want &%v", got, want)
	}
}

func TestParseAgentTags_DedupesAndDropsInvalid(t *testing.T) {
	got := parseAgentTags(
		"environment:production, BAD_KEY:value, team:platform, environment:production",
	)
	want := []string{"environment:production", "team:platform"}
	if got == nil || !reflect.DeepEqual(*got, want) {
		t.Errorf("got %v, want &%v", got, want)
	}
}

func TestParseAgentTags_EmptyValueReturnsNonNilEmptySlice(t *testing.T) {
	// Operator wrote ``tags =`` with no values.  Distinct from
	// "no [agent] section at all" — see AgentSection.Tags doc-
	// comment for the wire semantics.  parseAgentTags is only
	// called when the key was present, so the return value is
	// always non-nil.
	for _, in := range []string{"", "   ", ",,, ,,"} {
		got := parseAgentTags(in)
		if got == nil {
			t.Errorf("input %q: got nil, want &[]string{}", in)
			continue
		}
		if len(*got) != 0 {
			t.Errorf("input %q: got %v, want empty slice", in, *got)
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
	if got == nil || len(*got) != 32 {
		t.Errorf("expected cap at 32, got %v", got)
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
	if cfg.Agent.Tags == nil || !reflect.DeepEqual(*cfg.Agent.Tags, want) {
		t.Errorf("Agent.Tags: got %v, want &%v", cfg.Agent.Tags, want)
	}
}

func TestLoadFromFile_NoAgentSectionLeavesTagsNil(t *testing.T) {
	// When [agent] is absent entirely, Agent.Tags must be nil so
	// the wire emit omits the field (server leaves device.tags_agent
	// untouched — back-compat with older agents that don't know
	// about tags).  Distinct from the "tags =" empty case below.
	path := writeTempConfig(t, "[server]\nurl = https://example\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.Agent.Tags != nil {
		t.Errorf("expected nil, got %v", cfg.Agent.Tags)
	}
}

func TestLoadFromFile_EmptyTagsKeyClearsServerSide(t *testing.T) {
	// Operator wrote ``tags =`` with no values.  Agent.Tags must
	// be a non-nil empty slice so the wire emit is ``"tags": []``,
	// which the server interprets as "clear device.tags_agent".
	path := writeTempConfig(t, "[agent]\ntags =\n")
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.Agent.Tags == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(*cfg.Agent.Tags) != 0 {
		t.Errorf("expected empty slice, got %v", *cfg.Agent.Tags)
	}
}
