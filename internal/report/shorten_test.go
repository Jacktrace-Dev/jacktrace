package report

import "testing"

func TestShorten(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short text", 20, "short text"},
		{"exactly ten", 11, "exactly ten"},              // exactly max runes: kept whole
		{"too long for the limit", 10, "too long…"},     // max-1 runes, trailing space trimmed, then …
		{"first line\r\nsecond line", 20, "first line"}, // only the first line
		{"café naïve too long", 10, "café naïv…"},       // counts runes, not bytes
	}
	for _, tc := range cases {
		if got := shorten(tc.in, tc.max); got != tc.want {
			t.Errorf("shorten(%q, %d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}
