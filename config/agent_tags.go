// Tag parsing + validation for the ``[agent] tags = ...`` section.
//
// Mirrors the server's validation rules (sentari/server/services/
// device_tags.py) so an operator who copies a tag string from one
// to the other doesn't get surprised by a parser disagreement.
// Server is the ultimate authority — invalid tags would round-trip
// through the wire and be rejected with a 400 anyway — but doing
// the same check client-side keeps the agent's audit log clean and
// avoids one round-trip of useless server traffic.

package config

import (
	"log/slog"
	"regexp"
	"sort"
	"strings"
)

// tagRegex matches the same shape as
// ``server/services/device_tags.py:_TAG_RE``.
var tagRegex = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}:[A-Za-z0-9._-]{1,128}$`)

// maxAgentTags caps the per-source tag count.  Mirrors the server's
// ``MAX_TAGS_PER_SOURCE`` (32).  If an operator's agent.conf goes
// over, we keep the first 32 (post-dedupe + sort) and drop the rest
// with a warning rather than failing config-load — agent startup
// must succeed even on a sloppy edit.
const maxAgentTags = 32

// parseAgentTags splits an ``[agent] tags`` line on commas, trims
// whitespace, validates each entry against the regex, dedupes, and
// sorts.  Invalid entries are logged at WARN and dropped (don't
// block startup on a typo).
//
// Returns a *pointer* to a (possibly empty) slice — see
// ``AgentSection.Tags`` for the wire-state semantics.  This
// function is only called when the ``tags`` key was actually
// present in the config, so the return value is always non-nil
// (caller treats absence-of-key as nil at the AgentSection level).
func parseAgentTags(value string) *[]string {
	out := []string{}
	if strings.TrimSpace(value) == "" {
		return &out
	}
	seen := make(map[string]struct{})
	for _, raw := range strings.Split(value, ",") {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if !tagRegex.MatchString(t) {
			slog.Warn("config: dropping invalid agent tag",
				slog.String("tag", t))
			continue
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	if len(out) > maxAgentTags {
		slog.Warn("config: agent tags exceed cap; truncating",
			slog.Int("got", len(out)),
			slog.Int("max", maxAgentTags))
		out = out[:maxAgentTags]
	}
	return &out
}
