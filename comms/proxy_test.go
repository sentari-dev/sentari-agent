package comms

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRedactProxyURL asserts the credential-scrubbing helper masks any embedded
// password for both parseable and unparseable proxy URLs, so no error/log site
// that echoes the proxy URL can leak basic-auth credentials.
func TestRedactProxyURL(t *testing.T) {
	const secret = "sup3rsecret"
	tests := []struct {
		name         string
		raw          string
		wantContains string // a fragment that must survive redaction
		wantRedacted bool   // whether the "xxxxx" marker must be present
	}{
		{"parseable with user:pass", "https://user:" + secret + "@proxy:8080", "proxy:8080", true},
		{"parseable no creds", "http://proxy.corp:3128", "proxy.corp:3128", false},
		{"unparseable bad escape with creds", "http://user:" + secret + "%zz@proxy:8080", "proxy:8080", true},
		{"unparseable missing scheme with creds", "://user:" + secret + "@invalid", "invalid", true},
		// A bare username carries no password, so there is nothing to mask —
		// Go's Redacted() intentionally keeps it. The invariant we care about
		// (no password leak) still holds because there is no password.
		{"bare user no password", "http://user@proxy:3128", "proxy:3128", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactProxyURL(tt.raw)
			if strings.Contains(got, secret) {
				t.Errorf("redactProxyURL(%q) = %q leaks the password %q", tt.raw, got, secret)
			}
			if tt.wantRedacted && !strings.Contains(got, "xxxxx") {
				t.Errorf("redactProxyURL(%q) = %q missing redaction marker %q", tt.raw, got, "xxxxx")
			}
			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("redactProxyURL(%q) = %q should still contain %q", tt.raw, got, tt.wantContains)
			}
		})
	}
}

// TestBuildProxyFunc_errorsRedactCredentials proves that BOTH error sites in
// buildProxyFunc (parse failure and missing scheme) scrub an embedded proxy
// password before it reaches the returned error string — including the reason
// wrapped from url.Parse, whose *url.Error would otherwise print the raw URL
// verbatim.
func TestBuildProxyFunc_errorsRedactCredentials(t *testing.T) {
	const secret = "sup3rsecret"
	tests := []struct {
		name  string
		proxy string
	}{
		// Parse failure (bad percent-escape) — the wrapped *url.Error path.
		{"parse error", "http://user:" + secret + "%zz@proxy:8080"},
		// Scheme-relative URL parses cleanly but has an empty scheme, so it
		// hits the missing-scheme branch with credentials attached.
		{"missing scheme", "//user:" + secret + "@proxy:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildProxyFunc(ProxyConfig{HTTPSProxy: tt.proxy})
			if err == nil {
				t.Fatalf("expected error for %q", tt.proxy)
			}
			msg := err.Error()
			if strings.Contains(msg, secret) {
				t.Errorf("error string leaks proxy password: %q", msg)
			}
			if !strings.Contains(msg, "xxxxx") {
				t.Errorf("error string missing redaction marker: %q", msg)
			}
		})
	}
}

func TestParseNoProxy(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"empty", "", nil},
		{"single", "localhost", []string{"localhost"}},
		{"multiple", "localhost, 127.0.0.1, .corp.local", []string{"localhost", "127.0.0.1", ".corp.local"}},
		{"trims whitespace", "  foo ,  bar  ", []string{"foo", "bar"}},
		{"skips empty entries", "foo,,bar,", []string{"foo", "bar"}},
		{"lowercases", "FOO.COM, Bar.IO", []string{"foo.com", "bar.io"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseNoProxy(tt.input)
			if len(result) != len(tt.expected) {
				t.Fatalf("parseNoProxy(%q) = %v, want %v", tt.input, result, tt.expected)
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("parseNoProxy(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestShouldBypass(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		bypassList []string
		expected   bool
	}{
		{"exact match", "localhost", []string{"localhost"}, true},
		{"case insensitive", "LocalHost", []string{"localhost"}, true},
		{"no match", "proxy.com", []string{"localhost"}, false},
		{"dot-prefix suffix match", "foo.corp.local", []string{".corp.local"}, true},
		{"dot-prefix no match on exact domain", "corp.local", []string{".corp.local"}, false},
		{"bare domain suffix match", "sub.example.com", []string{"example.com"}, true},
		{"bare domain exact match", "example.com", []string{"example.com"}, true},
		{"wildcard", "anything.com", []string{"*"}, true},
		{"IP match", "127.0.0.1", []string{"127.0.0.1"}, true},
		{"IP no match", "10.0.0.1", []string{"127.0.0.1"}, false},
		{"empty bypass list", "host.com", nil, false},
		{"multiple entries match second", "api.internal", []string{"localhost", "api.internal"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldBypass(tt.host, tt.bypassList)
			if result != tt.expected {
				t.Errorf("shouldBypass(%q, %v) = %v, want %v", tt.host, tt.bypassList, result, tt.expected)
			}
		})
	}
}

func TestReadProxyPassword(t *testing.T) {
	t.Run("empty path returns empty", func(t *testing.T) {
		pw, err := readProxyPassword("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pw != "" {
			t.Errorf("expected empty string, got %q", pw)
		}
	})

	t.Run("reads and trims file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "proxy.pwd")
		if err := os.WriteFile(path, []byte("  s3cret\n  "), 0600); err != nil {
			t.Fatal(err)
		}
		pw, err := readProxyPassword(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pw != "s3cret" {
			t.Errorf("expected %q, got %q", "s3cret", pw)
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		_, err := readProxyPassword("/nonexistent/proxy.pwd")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestBuildProxyFunc(t *testing.T) {
	t.Run("basic proxy URL", func(t *testing.T) {
		proxyFunc, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "http://proxy.corp:3128",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req, _ := http.NewRequest("GET", "https://sentari.example.com/api", nil)
		proxyURL, err := proxyFunc(req)
		if err != nil {
			t.Fatalf("proxy func error: %v", err)
		}
		if proxyURL.Host != "proxy.corp:3128" {
			t.Errorf("expected proxy host proxy.corp:3128, got %s", proxyURL.Host)
		}
	})

	t.Run("auth from file overrides URL credentials", func(t *testing.T) {
		dir := t.TempDir()
		pwFile := filepath.Join(dir, "proxy.pwd")
		if err := os.WriteFile(pwFile, []byte("file_pass\n"), 0600); err != nil {
			t.Fatal(err)
		}
		proxyFunc, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy:   "https://urluser:urlpass@proxy.corp:3128",
			AuthUser:     "fileuser",
			AuthPassFile: pwFile,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		req, _ := http.NewRequest("GET", "https://sentari.example.com/api", nil)
		proxyURL, err := proxyFunc(req)
		if err != nil {
			t.Fatalf("proxy func error: %v", err)
		}
		if proxyURL.User.Username() != "fileuser" {
			t.Errorf("expected username fileuser, got %s", proxyURL.User.Username())
		}
		pw, _ := proxyURL.User.Password()
		if pw != "file_pass" {
			t.Errorf("expected password file_pass, got %s", pw)
		}
	})

	t.Run("NoProxy bypasses matching hosts", func(t *testing.T) {
		proxyFunc, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "http://proxy.corp:3128",
			NoProxy:    "sentari.internal, localhost",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Bypassed host should return nil.
		req, _ := http.NewRequest("GET", "https://sentari.internal:8000/api", nil)
		proxyURL, err := proxyFunc(req)
		if err != nil {
			t.Fatalf("proxy func error: %v", err)
		}
		if proxyURL != nil {
			t.Errorf("expected nil proxy for bypassed host, got %v", proxyURL)
		}

		// Non-bypassed host should return the proxy.
		req2, _ := http.NewRequest("GET", "https://external.com/api", nil)
		proxyURL2, err := proxyFunc(req2)
		if err != nil {
			t.Fatalf("proxy func error: %v", err)
		}
		if proxyURL2 == nil {
			t.Error("expected proxy URL for non-bypassed host, got nil")
		}
	})

	t.Run("missing scheme returns error", func(t *testing.T) {
		_, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "/proxy.corp:3128",
		})
		if err == nil {
			t.Fatal("expected error for missing scheme")
		}
	})

	t.Run("invalid URL returns error", func(t *testing.T) {
		_, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "://invalid",
		})
		if err == nil {
			t.Fatal("expected error for invalid URL")
		}
	})

	t.Run("auth user with missing password file returns error", func(t *testing.T) {
		_, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy:   "https://proxy.corp:3128",
			AuthUser:     "user",
			AuthPassFile: "/nonexistent/proxy.pwd",
		})
		if err == nil {
			t.Fatal("expected error for missing auth pass file")
		}
	})
}

// TestBuildProxyFunc_refusesCleartextProxyAuth proves the fail-closed rule for a
// cleartext proxy that carries credentials: an http:// proxy WITH proxy auth is
// refused at construction (the CONNECT would send Proxy-Authorization: Basic
// over cleartext), an http:// proxy WITHOUT auth is allowed (nothing to leak),
// and an https:// proxy WITH auth is allowed (credential rides inside TLS). The
// refusal must not surface any credential in its error string.
func TestBuildProxyFunc_refusesCleartextProxyAuth(t *testing.T) {
	const secret = "sup3rsecret"
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "proxy.pwd")
	if err := os.WriteFile(pwFile, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("http proxy with auth user is refused", func(t *testing.T) {
		_, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy:   "http://proxy.corp:3128",
			AuthUser:     "user",
			AuthPassFile: pwFile,
		})
		if err == nil {
			t.Fatal("expected refusal for http:// proxy with auth")
		}
		if !strings.Contains(err.Error(), "refusing to send proxy credentials over a cleartext http:// proxy") {
			t.Errorf("unexpected error message: %q", err.Error())
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("refusal error leaks the proxy credential: %q", err.Error())
		}
	})

	t.Run("http proxy with only auth pass file is refused", func(t *testing.T) {
		// AuthPassFile set without AuthUser is a misconfiguration; still refuse
		// fail-closed so no cleartext-proxy-auth path can slip through.
		_, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy:   "http://proxy.corp:3128",
			AuthPassFile: pwFile,
		})
		if err == nil {
			t.Fatal("expected refusal for http:// proxy with auth pass file")
		}
		if !strings.Contains(err.Error(), "refusing to send proxy credentials over a cleartext http:// proxy") {
			t.Errorf("unexpected error message: %q", err.Error())
		}
	})

	t.Run("http proxy without auth is allowed", func(t *testing.T) {
		if _, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "http://proxy.corp:3128",
		}); err != nil {
			t.Fatalf("http:// proxy without auth must be allowed, got: %v", err)
		}
	})

	t.Run("https proxy with auth is allowed", func(t *testing.T) {
		proxyFunc, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy:   "https://proxy.corp:3128",
			AuthUser:     "user",
			AuthPassFile: pwFile,
		})
		if err != nil {
			t.Fatalf("https:// proxy with auth must be allowed, got: %v", err)
		}
		req, _ := http.NewRequest("GET", "https://sentari.example.com/api", nil)
		proxyURL, err := proxyFunc(req)
		if err != nil {
			t.Fatalf("proxy func error: %v", err)
		}
		if pw, _ := proxyURL.User.Password(); pw != secret {
			t.Errorf("expected injected password on https proxy, got %q", pw)
		}
	})
}

// TestBuildProxyFunc_refusesCleartextProxyURLUserinfo covers the gap the
// separate-config guard missed: credentials embedded directly in the proxy URL
// userinfo (http://user:pass@proxy) with NO AuthUser/AuthPassFile set.  Go still
// sends Proxy-Authorization from the URL userinfo over the cleartext
// agent<->proxy segment, so this must be refused just like the config-supplied
// case — and the refusal must not leak the embedded credential.
func TestBuildProxyFunc_refusesCleartextProxyURLUserinfo(t *testing.T) {
	const secret = "sup3rsecret"

	t.Run("http proxy with userinfo credentials is refused", func(t *testing.T) {
		_, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "http://user:" + secret + "@proxy.corp:3128",
		})
		if err == nil {
			t.Fatal("expected refusal for http:// proxy with URL userinfo credentials")
		}
		if !strings.Contains(err.Error(), "refusing to send proxy credentials over a cleartext http:// proxy") {
			t.Errorf("unexpected error message: %q", err.Error())
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("refusal error leaks the proxy credential: %q", err.Error())
		}
	})

	t.Run("http proxy with bare userinfo username is refused", func(t *testing.T) {
		// A username-only userinfo still makes Go emit Proxy-Authorization;
		// refuse fail-closed.
		_, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "http://user@proxy.corp:3128",
		})
		if err == nil {
			t.Fatal("expected refusal for http:// proxy with bare userinfo username")
		}
		if !strings.Contains(err.Error(), "refusing to send proxy credentials over a cleartext http:// proxy") {
			t.Errorf("unexpected error message: %q", err.Error())
		}
	})

	t.Run("http proxy with no userinfo and no auth is allowed", func(t *testing.T) {
		if _, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "http://proxy.corp:3128",
		}); err != nil {
			t.Fatalf("http:// proxy without any credentials must be allowed, got: %v", err)
		}
	})

	t.Run("https proxy with userinfo credentials is allowed", func(t *testing.T) {
		proxyFunc, err := buildProxyFunc(ProxyConfig{
			HTTPSProxy: "https://user:" + secret + "@proxy.corp:3128",
		})
		if err != nil {
			t.Fatalf("https:// proxy with URL userinfo must be allowed, got: %v", err)
		}
		req, _ := http.NewRequest("GET", "https://sentari.example.com/api", nil)
		proxyURL, err := proxyFunc(req)
		if err != nil {
			t.Fatalf("proxy func error: %v", err)
		}
		if pw, _ := proxyURL.User.Password(); pw != secret {
			t.Errorf("expected userinfo password preserved on https proxy, got %q", pw)
		}
	})
}

// TestNewClient_refusesCleartextProxyAuth proves the refusal fires at the real
// client-construction chokepoint (NewClient), not only in the buildProxyFunc
// helper, so a misconfigured agent fails loudly at startup instead of shipping
// proxy credentials in cleartext.
func TestNewClient_refusesCleartextProxyAuth(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "proxy.pwd")
	if err := os.WriteFile(pwFile, []byte("sup3rsecret\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := NewClient(ClientConfig{
		ServerURL: "https://sentari.example.com",
		Proxy: ProxyConfig{
			HTTPSProxy:   "http://proxy.corp:3128",
			AuthUser:     "user",
			AuthPassFile: pwFile,
		},
	})
	if err == nil {
		t.Fatal("expected NewClient to refuse an http:// proxy with auth")
	}
	if !strings.Contains(err.Error(), "refusing to send proxy credentials over a cleartext http:// proxy") {
		t.Errorf("unexpected error: %q", err.Error())
	}

	// The same config over an https:// proxy must construct cleanly.
	if _, err := NewClient(ClientConfig{
		ServerURL: "https://sentari.example.com",
		Proxy: ProxyConfig{
			HTTPSProxy:   "https://proxy.corp:3128",
			AuthUser:     "user",
			AuthPassFile: pwFile,
		},
	}); err != nil {
		t.Fatalf("https:// proxy with auth must construct, got: %v", err)
	}
}

func TestNewClientWithProxy(t *testing.T) {
	t.Run("no proxy uses default behavior", func(t *testing.T) {
		client, err := NewClient(ClientConfig{
			ServerURL: "https://sentari.example.com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		transport := client.httpClient.Transport.(*http.Transport)
		if transport.Proxy != nil {
			t.Error("expected nil Proxy func when no proxy configured")
		}
	})

	t.Run("proxy is set on transport", func(t *testing.T) {
		client, err := NewClient(ClientConfig{
			ServerURL: "https://sentari.example.com",
			Proxy: ProxyConfig{
				HTTPSProxy: "http://proxy.corp:3128",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		transport := client.httpClient.Transport.(*http.Transport)
		if transport.Proxy == nil {
			t.Error("expected Proxy func to be set on transport")
		}

		// Verify the proxy function returns the correct URL.
		req, _ := http.NewRequest("GET", "https://sentari.example.com/api", nil)
		proxyURL, err := transport.Proxy(req)
		if err != nil {
			t.Fatalf("proxy func error: %v", err)
		}
		expected := "http://proxy.corp:3128"
		got := (&url.URL{Scheme: proxyURL.Scheme, Host: proxyURL.Host}).String()
		if got != expected {
			t.Errorf("expected proxy URL %s, got %s", expected, got)
		}
	})
}
