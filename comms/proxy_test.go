package comms

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

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
			HTTPSProxy:   "http://urluser:urlpass@proxy.corp:3128",
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
			HTTPSProxy:   "http://proxy.corp:3128",
			AuthUser:     "user",
			AuthPassFile: "/nonexistent/proxy.pwd",
		})
		if err == nil {
			t.Fatal("expected error for missing auth pass file")
		}
	})
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
