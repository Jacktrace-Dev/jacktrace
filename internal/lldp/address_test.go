package lldp

import "testing"

// Addresses are an IANA family byte (1 = IPv4, 2 = IPv6) followed by the address.
// Documentation ranges only: 192.0.2.0/24 and 2001:db8::/32.
var (
	ipv4 = []byte{1, 192, 0, 2, 10}
	ipv6 = []byte{2, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
)

func TestNetworkAddress(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"IPv4", ipv4, "192.0.2.10"},
		{"IPv6", ipv6, "2001:db8::1"},
		{"IPv4 family, too short", []byte{1, 192, 0, 2}, ""},
		{"IPv4 family, too long", []byte{1, 192, 0, 2, 10, 0}, ""},
		{"IPv6 family, IPv4-sized address", []byte{2, 192, 0, 2, 10}, ""},
		{"IPv6 family, too long", append(append([]byte{}, ipv6...), 0), ""},
		{"unknown family, IPv4-sized", []byte{6, 192, 0, 2, 10}, ""},
		{"unknown family, IPv6-sized", append([]byte{6}, ipv6[1:]...), ""},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		if got := networkAddress(tc.in); got != tc.want {
			t.Errorf("%s: networkAddress = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A Management Address TLV starts with the address string length (family byte included),
// then the address; interface numbering and an OID follow and are ignored.
func TestMgmtAddress(t *testing.T) {
	// full slice expression: no spare capacity, so reading past the end panics instead of
	// quietly finding zero bytes there
	withLen := func(l byte, rest ...byte) []byte { b := append([]byte{l}, rest...); return b[:len(b):len(b)] }
	trailer := []byte{2, 0, 0, 0, 7, 0} // interface numbering subtype + number + OID length
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"IPv4", withLen(5, ipv4...), "192.0.2.10"},
		{"IPv4 with trailing fields", append(withLen(5, ipv4...), trailer...), "192.0.2.10"},
		{"IPv6", withLen(17, ipv6...), "2001:db8::1"},
		{"empty", nil, ""},
		{"one byte", []byte{5}, ""},
		{"length below 2", withLen(1, ipv4...), ""},
		{"length runs past the end", withLen(6, ipv4...), ""},
		{"length fits but address is wrong size", withLen(4, ipv4...), ""},
	}
	for _, tc := range cases {
		if got := mgmtAddress(tc.in); got != tc.want {
			t.Errorf("%s: mgmtAddress = %q, want %q", tc.name, got, tc.want)
		}
	}
}
