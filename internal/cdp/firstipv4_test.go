package cdp

import "testing"

// Address lists: a big-endian count, then per entry protocol type, protocol length,
// protocol, a big-endian address length and the address. IPv4 is type 1, length 1, 0xCC.
func TestFirstIPv4(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"fewer than 4 bytes", []byte{0, 0, 0}, ""},
		{"cut off in the protocol header", []byte{0, 0, 0, 1, 1}, ""},
		{"cut off in the protocol", []byte{0, 0, 0, 1, 1, 1, 0xCC}, ""},
		{"cut off in the address length", []byte{0, 0, 0, 1, 1, 1, 0xCC, 0}, ""},
		{"cut off in the address", []byte{0, 0, 0, 1, 1, 1, 0xCC, 0, 4, 192, 0, 2}, ""},
		{"non-IP entry, then IPv4", []byte{0, 0, 0, 2, 1, 1, 0xAA, 0, 4, 192, 0, 2, 10, 1, 1, 0xCC, 0, 4, 192, 0, 2, 20}, "192.0.2.20"},
		{"no IPv4 entry", []byte{0, 0, 0, 1, 1, 1, 0xAA, 0, 4, 192, 0, 2, 10}, ""},
	}
	for _, tc := range cases {
		if got := firstIPv4(tc.in); got != tc.want {
			t.Errorf("%s: firstIPv4 = %q, want %q", tc.name, got, tc.want)
		}
	}
}
