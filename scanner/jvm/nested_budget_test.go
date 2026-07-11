package jvm

import (
	mathrand "math/rand"
	"strings"
	"testing"
)

// TestExtractFromJar_NestedByteBudgetEnforced proves the cumulative
// in-flight byte budget (maxNestedInFlightBytes) fires: several sibling
// nested jars, each large enough that their sum exceeds a deliberately
// lowered budget, must trip a "byte budget" ScanError partway through
// rather than materialising every member.  Without the budget a wide
// fan-out of just-under-cap members (or a deflate bomb) could pin far
// more memory than a single member's cap implies.
//
// The budget is lowered via the package var so the test stays cheap —
// no need to build 256 MiB of fixtures to exercise the same code path.
func TestExtractFromJar_NestedByteBudgetEnforced(t *testing.T) {
	orig := maxNestedInFlightBytes
	maxNestedInFlightBytes = 12 * 1024 // 12 KiB
	t.Cleanup(func() { maxNestedInFlightBytes = orig })

	// Incompressible padding so each nested jar's *own* byte length is
	// substantial (deflate can't shrink random bytes) — otherwise the
	// stored nested jar would be a few hundred bytes and never reach
	// the budget.  A fixed seed keeps the fixture deterministic.
	pad := make([]byte, 8000)
	mathrand.New(mathrand.NewSource(42)).Read(pad)

	mkInner := func(id string) []byte {
		return buildJARBytes(t, map[string][]byte{
			"META-INF/maven/n/" + id + "/pom.properties": []byte(
				"groupId=n\nartifactId=" + id + "\nversion=1\n"),
			"pad.bin": pad,
		})
	}

	outer := buildJAR(t, map[string][]byte{
		"BOOT-INF/lib/a.jar": mkInner("a"),
		"BOOT-INF/lib/b.jar": mkInner("b"),
		"BOOT-INF/lib/c.jar": mkInner("c"),
		"BOOT-INF/lib/d.jar": mkInner("d"),
	})

	records, errs := extractFromJar(outer)

	// At least one budget ScanError must be present.
	budgetErrs := 0
	for _, e := range errs {
		if strings.Contains(e.Error, "byte budget") {
			budgetErrs++
		}
	}
	if budgetErrs == 0 {
		t.Fatalf("expected a nested-jar byte-budget ScanError, got errs=%+v", errs)
	}

	// The budget must have skipped at least one nested dependency: with
	// four ~8 KiB inners and a 12 KiB budget, only the first fits.
	nestedRecords := 0
	for _, r := range records {
		if strings.Contains(r.InstallPath, "!/BOOT-INF/lib/") {
			nestedRecords++
		}
	}
	if nestedRecords >= 4 {
		t.Errorf("budget did not skip any nested member: got %d nested records", nestedRecords)
	}
}

// TestExtractFromJar_WithinBudgetYieldsAllRecords is the negative
// control: with the default (large) budget, the same fan-out of small
// nested jars is fully extracted — the budget only bites on abuse, not
// on legitimate uber-jars.
func TestExtractFromJar_WithinBudgetYieldsAllRecords(t *testing.T) {
	mkInner := func(id string) []byte {
		return buildJARBytes(t, map[string][]byte{
			"META-INF/maven/n/" + id + "/pom.properties": []byte(
				"groupId=n\nartifactId=" + id + "\nversion=1\n"),
		})
	}
	outer := buildJAR(t, map[string][]byte{
		"BOOT-INF/lib/a.jar": mkInner("a"),
		"BOOT-INF/lib/b.jar": mkInner("b"),
		"BOOT-INF/lib/c.jar": mkInner("c"),
	})

	records, errs := extractFromJar(outer)
	for _, e := range errs {
		if strings.Contains(e.Error, "byte budget") {
			t.Fatalf("unexpected budget error under default budget: %+v", errs)
		}
	}
	seen := map[string]bool{}
	for _, r := range records {
		seen[r.Name] = true
	}
	for _, want := range []string{"n:a", "n:b", "n:c"} {
		if !seen[want] {
			t.Errorf("expected nested record %q under default budget, got %v", want, seen)
		}
	}
}
