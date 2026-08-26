package scanner

import (
	"strings"
	"testing"
)

func TestNormalizeSupplier(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain name", "Acme Corp", "Acme Corp"},
		{"name with email", "John Doe <john@example.com>", "John Doe"},
		{"email only", "john@example.com", ""},
		{"angle email only", "<john@example.com>", ""},
		{"npm author string", "Sindre Sorhus <sindre@sindresorhus.com> (https://sindresorhus.com)", "Sindre Sorhus"},
		{"npm author no name", "<sindre@sindresorhus.com> (https://sindresorhus.com)", ""},
		{"deb team", "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", "Ubuntu Developers"},
		{"multi author", "John Doe <a@x.com>, Jane Roe <b@y.com>", "John Doe, Jane Roe"},
		{"multi author one email-only", "John Doe <a@x.com>, b@y.com", "John Doe"},
		{"quoted", "\"Acme Corp\"", "Acme Corp"},
		{"whitespace collapse", "  Acme   Corp  ", "Acme Corp"},
		{"unknown placeholder", "UNKNOWN", ""},
		{"unknown mixed case", "unknown", ""},
		{"none placeholder", "None", ""},
		{"none lower", "none", ""},
		{"apostrophe name preserved", "'t Hooft", "'t Hooft"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"tabs and newlines", "Acme\tCorp", "Acme Corp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeSupplier(tc.in); got != tc.want {
				t.Errorf("NormalizeSupplier(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeSupplierLengthCap(t *testing.T) {
	long := strings.Repeat("A", 300)
	got := NormalizeSupplier(long)
	if len([]rune(got)) != maxSupplierLen {
		t.Errorf("length = %d, want %d", len([]rune(got)), maxSupplierLen)
	}
}

func TestNormalizeSupplierUnicodeCap(t *testing.T) {
	// Multi-byte runes must be capped by rune count, not byte count, and must
	// never split a rune (which would corrupt the UTF-8 on the wire).
	long := strings.Repeat("é", 300)
	got := NormalizeSupplier(long)
	if runes := []rune(got); len(runes) != maxSupplierLen {
		t.Errorf("rune length = %d, want %d", len(runes), maxSupplierLen)
	}
	if !strings.ContainsRune(got, 'é') || strings.ContainsRune(got, '�') {
		t.Errorf("unicode corrupted: %q", got)
	}
}

func TestExtractSupplierFromMetadata(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"author wins",
			"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\nAuthor: Acme Corp\nAuthor-email: dev@acme.com\n",
			"Acme Corp",
		},
		{
			"author-email name-part fallback",
			"Name: pkg\nVersion: 1.0\nAuthor-email: Acme Corp <dev@acme.com>\n",
			"Acme Corp",
		},
		{
			"maintainer fallback",
			"Name: pkg\nVersion: 1.0\nAuthor-email: dev@acme.com\nMaintainer: Bob Maintainer\n",
			"Bob Maintainer",
		},
		{
			"maintainer-email last resort",
			"Name: pkg\nVersion: 1.0\nMaintainer-email: Carol <carol@x.com>\n",
			"Carol",
		},
		{
			"unknown author skipped",
			"Name: pkg\nVersion: 1.0\nAuthor: UNKNOWN\nMaintainer: Real Team\n",
			"Real Team",
		},
		{
			"body author ignored",
			"Name: pkg\nVersion: 1.0\n\nAuthor: In The Body\n",
			"",
		},
		{
			"nothing usable",
			"Name: pkg\nVersion: 1.0\nAuthor-email: dev@acme.com\n",
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractSupplierFromMetadata(tc.in); got != tc.want {
				t.Errorf("extractSupplierFromMetadata() = %q, want %q", got, tc.want)
			}
		})
	}
}
