package report

import "testing"

func TestPortVLANs(t *testing.T) {
	cases := []struct {
		data, voice int
		want        string
	}{
		{20, 120, "20 data · 120 voice"},
		{20, 0, "20"},
		{0, 120, "120 voice"},
		{0, 0, ""},
	}
	for _, tc := range cases {
		p := Port{NativeVLAN: tc.data, VoiceVLAN: tc.voice}
		if got := p.VLANs(); got != tc.want {
			t.Errorf("VLANs() for data %d voice %d = %q, want %q", tc.data, tc.voice, got, tc.want)
		}
	}
}
