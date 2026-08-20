package sbom

import (
	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// CycloneDXNamedLicense is the CycloneDX "named license" form, used as the
// fallback when only a raw (non-SPDX) license string is known.
type CycloneDXNamedLicense struct {
	Name string `json:"name"`
}

// CycloneDXLicenseChoice is one entry in a component's "licenses" array. It is
// either the SPDX-expression form ({"expression": "<spdx>"}) or the named form
// ({"license": {"name": "<raw>"}}); exactly one of the two is set.
type CycloneDXLicenseChoice struct {
	Expression string                 `json:"expression,omitempty"`
	License    *CycloneDXNamedLicense `json:"license,omitempty"`
}

// licenseIndex maps a package coordinate to the single best license-evidence
// row observed for it.
type licenseIndex map[string]deptree.LicenseEvidence

// licenseEvidenceBetter reports whether a should replace b as the best evidence
// for a coordinate. The total order is: higher Confidence first, then Source,
// SpdxID, and RawText ascending — fully deterministic under any input order.
func licenseEvidenceBetter(a, b deptree.LicenseEvidence) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.SpdxID != b.SpdxID {
		return a.SpdxID < b.SpdxID
	}
	return a.RawText < b.RawText
}

// newLicenseIndex reduces the scan's license evidence to the best row per
// coordinate. Rows whose ecosystem produces no coordinate key are ignored.
func newLicenseIndex(evidence []deptree.LicenseEvidence) licenseIndex {
	idx := make(licenseIndex, len(evidence))
	for _, ev := range evidence {
		key := coordKey(ev.Ecosystem, ev.PackageName, ev.PackageVersion)
		if key == "" {
			continue
		}
		if existing, ok := idx[key]; !ok || licenseEvidenceBetter(ev, existing) {
			idx[key] = ev
		}
	}
	return idx
}

// componentLicenses holds the format-specific license projections for one
// component.
type componentLicenses struct {
	cyclonedx []CycloneDXLicenseChoice
	concluded string
	declared  string
	copyright string
}

// resolveComponentLicenses projects a package record (plus the scan's license
// evidence) into CycloneDX and SPDX license shapes.
//
// SPDX expression precedence: the record's normalized LicenseSPDX, else the
// best evidence SpdxID for the coordinate. A non-empty value is trusted as a
// valid SPDX identifier by construction — the scanner only ever writes values
// drawn from its normalization maps, so no separate validity table is needed.
//
// CycloneDX:
//   - known SPDX expression → [{"expression": "<spdx>"}];
//   - else raw license only → [{"license": {"name": "<raw>"}}]. This name-form
//     fallback is a deliberate superset: it carries the raw string the SPDX
//     expression form cannot represent, so the output is more complete for
//     records that lack a normalized id;
//   - else → nil (the caller omits the "licenses" key entirely — never a
//     NOASSERTION placeholder).
//
// SPDX: concluded = expression or "NOASSERTION"; declared = raw or
// "NOASSERTION"; copyright = best evidence RawText or "NOASSERTION".
func resolveComponentLicenses(pkg scanner.PackageRecord, idx licenseIndex) componentLicenses {
	var ev deptree.LicenseEvidence
	var haveEv bool
	if key := coordKey(envTypeEcosystem(pkg.EnvType), pkg.Name, pkg.Version); key != "" {
		ev, haveEv = idx[key]
	}

	spdxExpr := pkg.LicenseSPDX
	if spdxExpr == "" && haveEv {
		spdxExpr = ev.SpdxID
	}

	concluded := "NOASSERTION"
	if spdxExpr != "" {
		concluded = spdxExpr
	}
	declared := "NOASSERTION"
	if pkg.LicenseRaw != "" {
		declared = pkg.LicenseRaw
	}
	copyright := "NOASSERTION"
	if haveEv && ev.RawText != "" {
		copyright = ev.RawText
	}

	var cdx []CycloneDXLicenseChoice
	switch {
	case spdxExpr != "":
		cdx = []CycloneDXLicenseChoice{{Expression: spdxExpr}}
	case pkg.LicenseRaw != "":
		cdx = []CycloneDXLicenseChoice{{License: &CycloneDXNamedLicense{Name: pkg.LicenseRaw}}}
	}

	return componentLicenses{cyclonedx: cdx, concluded: concluded, declared: declared, copyright: copyright}
}
