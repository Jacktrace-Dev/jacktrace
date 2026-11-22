package lldp

import "testing"

func TestMauType(t *testing.T) {
	cases := []struct {
		in            uint16
		media, duplex string
	}{
		{10, "10BASE-T", "half"},
		{11, "10BASE-T", "full"},
		{15, "100BASE-TX", "half"},
		{16, "100BASE-TX", "full"},
		{29, "1000BASE-T", "half"},
		{30, "1000BASE-T", "full"},
		{0, "", ""},
		{999, "MAU type 999", ""},
	}
	for _, tc := range cases {
		media, duplex := mauType(tc.in)
		if media != tc.media || duplex != tc.duplex {
			t.Errorf("mauType(%d) = (%q, %q), want (%q, %q)", tc.in, media, duplex, tc.media, tc.duplex)
		}
	}
}
