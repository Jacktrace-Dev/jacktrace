package discovery

import "testing"

func TestCleanText(t *testing.T) {
	cases := map[string]string{
		"  IDF2-ACCESS-01\x00\x00": "IDF2-ACCESS-01",
		"a\x1b[31mred\x1b[0m":      "a[31mred[0m",
		"tab\there":                "tab here",
		"bad\xffutf8":              "bad�utf8",
		"Göteborg-SW1":             "Göteborg-SW1",
	}
	for in, want := range cases {
		if got := CleanText([]byte(in)); got != want {
			t.Errorf("CleanText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatMAC(t *testing.T) {
	if got := FormatMAC([]byte{0x02, 0x4A, 0x54, 0, 0, 1}); got != "02:4a:54:00:00:01" {
		t.Errorf("got %q", got)
	}
	if got := FormatMAC([]byte{1, 2, 3}); got != "010203" {
		t.Errorf("odd length: got %q", got)
	}
}
