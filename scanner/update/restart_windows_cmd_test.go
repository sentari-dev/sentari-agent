package update

import (
	"strings"
	"testing"
)

func TestWindowsServiceName(t *testing.T) {
	cases := []struct {
		env     string
		want    string
		wantErr bool
	}{
		{"", "SentariAgent", false},             // default
		{"SentariAgent", "SentariAgent", false}, // explicit default
		{"my-agent_01", "my-agent_01", false},   // allowed charset
		{"bad name", "", true},                  // space
		{`svc & calc.exe`, "", true},            // metacharacter
		{`..\..\evil`, "", true},                // separators
		{"-leadingdash", "", true},              // leading non-alphanumeric
	}
	for _, c := range cases {
		got, err := windowsServiceName(c.env)
		if c.wantErr {
			if err == nil {
				t.Errorf("windowsServiceName(%q) = %q, want error", c.env, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("windowsServiceName(%q) unexpected error: %v", c.env, err)
		}
		if got != c.want {
			t.Errorf("windowsServiceName(%q) = %q, want %q", c.env, got, c.want)
		}
	}
}

func TestWindowsRestartCommandLine(t *testing.T) {
	got := windowsRestartCommandLine("SentariAgent")
	for _, want := range []string{"sc stop SentariAgent", "sc start SentariAgent", "timeout"} {
		if !strings.Contains(got, want) {
			t.Errorf("command line %q missing %q", got, want)
		}
	}
	// Stop must precede start.
	if strings.Index(got, "sc stop") > strings.Index(got, "sc start") {
		t.Errorf("stop should precede start: %q", got)
	}
}
