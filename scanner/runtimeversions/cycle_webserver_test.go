package runtimeversions

import "testing"

func TestCycleForWebServers(t *testing.T) {
	cases := map[string]string{"nginx": "1.24", "apache-httpd": "2.4"}
	versions := map[string]string{"nginx": "1.24.0", "apache-httpd": "2.4.58"}
	for name, want := range cases {
		if got := CycleFor(name, versions[name]); got != want {
			t.Fatalf("CycleFor(%q,%q)=%q want %q", name, versions[name], got, want)
		}
	}
}

func TestWebServerRuntimeNames(t *testing.T) {
	got := WebServerRuntimeNames()
	want := []string{"apache-httpd", "iis", "nginx"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
