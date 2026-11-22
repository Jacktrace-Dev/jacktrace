package discovery

import "testing"

func TestValidVLAN(t *testing.T) {
	cases := []struct {
		v    int
		want bool
	}{
		{-1, false}, {0, false}, {1, true}, {20, true}, {4094, true}, {4095, false}, {4096, false},
	}
	for _, tc := range cases {
		if got := ValidVLAN(tc.v); got != tc.want {
			t.Errorf("ValidVLAN(%d) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
