package runtimeversions

import "testing"

func TestCycleForBrokers(t *testing.T) {
	cases := map[string]struct{ ver, want string }{
		"rabbitmq":         {"3.12.0", "3.12"},
		"kafka":            {"3.7.0", "3.7"},
		"activemq":         {"5.18.3", "5.18"},
		"activemq-artemis": {"2.33.0", "2.33"},
	}
	for name, c := range cases {
		if got := CycleFor(name, c.ver); got != c.want {
			t.Fatalf("CycleFor(%q,%q)=%q want %q", name, c.ver, got, c.want)
		}
	}
}

func TestBrokerRuntimeNames(t *testing.T) {
	got := BrokerRuntimeNames()
	want := []string{"activemq", "activemq-artemis", "kafka", "rabbitmq"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
