package scanner

import (
	"regexp"
	"strings"
)

// maxSupplierLen bounds a supplier string on the wire. The server truncates
// to 255 characters at persist time (_clean_supplier); the agent caps here
// too so an oversized or hostile metadata field never bloats the payload.
const maxSupplierLen = 255

// supplierEmailRe matches an RFC-822 angle-bracket email/address segment,
// e.g. the "<a@b.c>" in `Name <a@b.c>` (deb Maintainer, pypi Author-email,
// npm author-string).
var supplierEmailRe = regexp.MustCompile(`<[^>]*>`)

// supplierURLRe matches a parenthesised URL, the trailing "(https://…)" of
// the npm author-string convention `Name <email> (url)`.
var supplierURLRe = regexp.MustCompile(`\(https?://[^)]*\)`)

// NormalizeSupplier sanitizes a raw supplier/author string read from local
// package metadata into the value emitted on PackageRecord.Supplier. It:
//
//   - removes angle-bracket email segments ("Name <a@b.c>" → "Name"),
//   - removes parenthesised URLs (the npm "(https://…)" author suffix),
//   - drops any remaining bare email-like ("@") or URL-like ("://") tokens,
//   - preserves comma-separated multi-author lists (re-joined as ", "),
//   - collapses internal whitespace and trims surrounding quotes/space,
//   - discards the pypi "UNKNOWN" placeholder,
//   - caps the result at maxSupplierLen runes.
//
// It returns "" when nothing usable remains (e.g. an email-only Author-email,
// or a bare "UNKNOWN"), in which case callers omit the field. The NTIA
// supplier element wants an organization/person NAME; shipping maintainer
// emails into auditor-facing SBOMs is gratuitous PII (spec §4.2 / §7.4), so
// the sanitizer strips them by default. Shared across every ecosystem so the
// stripping rule can never drift between scanners.
func NormalizeSupplier(raw string) string {
	s := supplierEmailRe.ReplaceAllString(raw, " ")
	s = supplierURLRe.ReplaceAllString(s, " ")

	var segments []string
	for _, seg := range strings.Split(s, ",") {
		var tokens []string
		for _, tok := range strings.Fields(seg) {
			// A leftover bare email or URL token is stray identity noise,
			// not a name — drop it (handles Author-email lists and npm
			// author strings without a name part).
			if strings.Contains(tok, "@") || strings.Contains(tok, "://") {
				continue
			}
			tokens = append(tokens, tok)
		}
		if joined := strings.Join(tokens, " "); joined != "" {
			segments = append(segments, joined)
		}
	}

	out := strings.Trim(strings.Join(segments, ", "), " \t\"'")
	if out == "" || strings.EqualFold(out, "UNKNOWN") {
		return ""
	}
	if runes := []rune(out); len(runes) > maxSupplierLen {
		out = string(runes[:maxSupplierLen])
	}
	return out
}

// extractSupplierFromMetadata reads the supplier (author/maintainer) name from
// a Python METADATA / PKG-INFO file's RFC-822 headers, applying PEP-621-ish
// precedence: Author → Author-email → Maintainer → Maintainer-email, taking
// the first that yields a non-empty NormalizeSupplier result. Only the header
// block is scanned (stops at the first blank line) so a long-description body
// containing an "Author:" line cannot override the real field — mirroring
// ExtractLicenseFromMetadata. Returns "" when no usable name is present
// (common: many packages set only an email, or nothing).
func extractSupplierFromMetadata(content string) string {
	var author, authorEmail, maintainer, maintainerEmail string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			// End of the RFC-822 header block.
			break
		}
		switch {
		case strings.HasPrefix(line, "Author-email:"):
			authorEmail = strings.TrimSpace(strings.TrimPrefix(line, "Author-email:"))
		case strings.HasPrefix(line, "Author:"):
			author = strings.TrimSpace(strings.TrimPrefix(line, "Author:"))
		case strings.HasPrefix(line, "Maintainer-email:"):
			maintainerEmail = strings.TrimSpace(strings.TrimPrefix(line, "Maintainer-email:"))
		case strings.HasPrefix(line, "Maintainer:"):
			maintainer = strings.TrimSpace(strings.TrimPrefix(line, "Maintainer:"))
		}
	}
	for _, candidate := range []string{author, authorEmail, maintainer, maintainerEmail} {
		if s := NormalizeSupplier(candidate); s != "" {
			return s
		}
	}
	return ""
}
