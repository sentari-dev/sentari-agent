package plist

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// readFixture loads a testdata plist file.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// TestParse_XMLAndBinaryAgree parses the XML and binary encodings of the same
// documents and asserts the decoded Go values are identical — the from-scratch
// bplist parser must produce the same tree as encoding/xml.
func TestParse_XMLAndBinaryAgree(t *testing.T) {
	pairs := []struct{ xmlName, binName string }{
		{"screensaver_xml.plist", "screensaver_bin.plist"},
		{"alf_xml.plist", "alf_bin.plist"},
		{"softwareupdate_xml.plist", "softwareupdate_bin.plist"},
		{"rich_xml.plist", "rich_bin.plist"},
	}
	for _, p := range pairs {
		p := p
		t.Run(p.binName, func(t *testing.T) {
			xv, err := Parse(readFixture(t, p.xmlName))
			if err != nil {
				t.Fatalf("xml parse: %v", err)
			}
			bv, err := Parse(readFixture(t, p.binName))
			if err != nil {
				t.Fatalf("bin parse: %v", err)
			}
			if !reflect.DeepEqual(xv, bv) {
				t.Fatalf("xml != bin\n xml=%#v\n bin=%#v", xv, bv)
			}
		})
	}
}

// TestParse_BinaryObjectTypes asserts every supported object type decodes to
// the expected Go value from the rich fixture.
func TestParse_BinaryObjectTypes(t *testing.T) {
	v, err := Parse(readFixture(t, "rich_bin.plist"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("root not dict: %T", v)
	}
	if got := m["unicodeName"]; got != "café—Zürich" { // UTF-16 string
		t.Errorf("unicodeName=%q", got)
	}
	if got := m["ratio"]; got != 0.5 { // real (8-byte double)
		t.Errorf("ratio=%v", got)
	}
	if got := m["count"]; got != int64(300) { // 2-byte int
		t.Errorf("count=%v", got)
	}
	arr, ok := m["flags"].([]any)
	if !ok || len(arr) != 4 {
		t.Fatalf("flags not 4-array: %#v", m["flags"])
	}
	if arr[0] != true || arr[1] != false || arr[2] != int64(7) || arr[3] != "ok" {
		t.Errorf("flags contents = %#v", arr)
	}
	nested, ok := m["nested"].(map[string]any)
	if !ok || nested["inner"] != int64(42) {
		t.Errorf("nested = %#v", m["nested"])
	}
}

// TestGetHelpers exercises the navigation helpers on a decoded tree.
func TestGetHelpers(t *testing.T) {
	v, err := Parse(readFixture(t, "screensaver_xml.plist"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root, _ := v.(map[string]any)

	if b, ok := Int(root, "askForPassword"); !ok || b != 1 {
		t.Errorf("askForPassword Int = %d,%v", b, ok)
	}
	if s, ok := String(root, "moduleName"); !ok || s != "Flurry" {
		t.Errorf("moduleName String = %q,%v", s, ok)
	}
	if b, ok := Bool(root, "showClock"); !ok || !b {
		t.Errorf("showClock Bool = %v,%v", b, ok)
	}
	// Missing key.
	if _, ok := Int(root, "nope"); ok {
		t.Errorf("expected missing key to report ok=false")
	}
}

// TestBool_FromInt covers the int-as-bool coercion path used by ALF/SoftwareUpdate.
func TestBool_FromInt(t *testing.T) {
	v, _ := Parse(readFixture(t, "alf_xml.plist"))
	root, _ := v.(map[string]any)
	if b, ok := Bool(root, "globalstate"); !ok || !b {
		t.Errorf("globalstate as bool = %v,%v", b, ok)
	}
	if b, ok := Bool(root, "loggingenabled"); !ok || b {
		t.Errorf("loggingenabled as bool = %v,%v", b, ok)
	}
}

func TestParse_Errors(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"unknown format":   []byte("not a plist at all"),
		"short binary":     append([]byte("bplist00"), 0x00),
		"bad trailer size": append(append([]byte("bplist00"), make([]byte, 8)...), make([]byte, 32)...),
	}
	for name, data := range cases {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

// TestParse_XMLReal confirms the XML real/data paths decode.
func TestParse_XMLReal(t *testing.T) {
	v, err := Parse(readFixture(t, "softwareupdate_xml.plist"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m := v.(map[string]any)
	if m["AutomaticCheckEnabled"] != true {
		t.Errorf("AutomaticCheckEnabled=%v", m["AutomaticCheckEnabled"])
	}
	if m["LastFullSuccessfulDate"] != 1234.5 {
		t.Errorf("real=%v", m["LastFullSuccessfulDate"])
	}
}
