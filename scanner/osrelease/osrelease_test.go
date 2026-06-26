package osrelease

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		name    string
		data    string
		wantID  string
		wantVer string
		wantOK  bool
	}{
		{
			name:    "debian 12",
			data:    "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			wantID:  "debian",
			wantVer: "12",
			wantOK:  true,
		},
		{
			name:    "ubuntu 22.04",
			data:    "ID=ubuntu\nVERSION_ID=\"22.04\"\nID_LIKE=debian\n",
			wantID:  "ubuntu",
			wantVer: "22.04",
			wantOK:  true,
		},
		{
			name:    "rocky 9.3 unquoted",
			data:    "ID=\"rocky\"\nVERSION_ID=\"9.3\"\n",
			wantID:  "rocky",
			wantVer: "9.3",
			wantOK:  true,
		},
		{
			name:    "fedora 40",
			data:    "ID=fedora\nVERSION_ID=40\n",
			wantID:  "fedora",
			wantVer: "40",
			wantOK:  true,
		},
		{
			name:   "missing ID -> not detected",
			data:   "VERSION_ID=\"12\"\nPRETTY_NAME=mystery\n",
			wantOK: false,
		},
		{
			name:   "comments and blanks ignored",
			data:   "# a comment\n\nID=debian\n\n# another\nVERSION_ID=13\n",
			wantID: "debian", wantVer: "13", wantOK: true,
		},
		{
			name:   "empty file",
			data:   "",
			wantOK: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, ok := parse([]byte(tc.data))
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if res.ID != tc.wantID || res.VersionID != tc.wantVer {
				t.Fatalf("got (%q,%q), want (%q,%q)", res.ID, res.VersionID, tc.wantID, tc.wantVer)
			}
		})
	}
}
