package report

import "testing"

func TestJoinAdapters(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{nil, "no adapters"},
		{[]string{"Ethernet"}, "Ethernet"},
		{[]string{"Ethernet", "Ethernet 2"}, "Ethernet and Ethernet 2"},
		{[]string{"Ethernet", "Ethernet 2", "Ethernet 3", "Ethernet 4"}, "Ethernet and 3 more"},
	}
	for _, tc := range cases {
		if got := joinAdapters(tc.names); got != tc.want {
			t.Errorf("joinAdapters(%q) = %q, want %q", tc.names, got, tc.want)
		}
	}
}
