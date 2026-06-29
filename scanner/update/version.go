package update

import (
	"fmt"
	"strconv"
	"strings"
)

// semver holds a parsed MAJOR.MINOR.PATCH core triple.  Pre-release and
// build metadata suffixes are tolerated on input but ignored for
// comparison: the self-update gate only reasons about the release
// triple, matching how the server stamps released versions.
type semver struct {
	major, minor, patch int
}

// parseSemver parses a version string of the form ``MAJOR.MINOR.PATCH``
// with an optional leading ``v`` and an optional pre-release/build
// suffix (``-rc1`` or ``+build5``) which is discarded.  A missing minor
// or patch component is treated as zero (``1.2`` == ``1.2.0``).  An
// unparseable version is rejected with an error so a malformed or
// malicious manifest can never be silently accepted.
func parseSemver(v string) (semver, error) {
	s := strings.TrimSpace(v)
	if s == "" {
		return semver{}, fmt.Errorf("empty version")
	}
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")

	// Strip pre-release / build metadata: everything from the first
	// '-' or '+' onward applies to the core triple only.
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}

	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, fmt.Errorf("invalid version %q: want MAJOR.MINOR.PATCH", v)
	}

	out := semver{}
	for idx := 0; idx < 3; idx++ {
		if idx >= len(parts) {
			break // missing component → already zero
		}
		p := parts[idx]
		if p == "" {
			return semver{}, fmt.Errorf("invalid version %q: empty component", v)
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, fmt.Errorf("invalid version %q: non-numeric component %q", v, p)
		}
		switch idx {
		case 0:
			out.major = n
		case 1:
			out.minor = n
		case 2:
			out.patch = n
		}
	}
	return out, nil
}

// compareVersions returns -1 if a < b, 0 if equal, +1 if a > b, by the
// parsed core triple.  Returns an error if either version is
// unparseable.
func compareVersions(a, b string) (int, error) {
	sa, err := parseSemver(a)
	if err != nil {
		return 0, err
	}
	sb, err := parseSemver(b)
	if err != nil {
		return 0, err
	}
	for _, pair := range [][2]int{
		{sa.major, sb.major},
		{sa.minor, sb.minor},
		{sa.patch, sb.patch},
	} {
		switch {
		case pair[0] < pair[1]:
			return -1, nil
		case pair[0] > pair[1]:
			return 1, nil
		}
	}
	return 0, nil
}
