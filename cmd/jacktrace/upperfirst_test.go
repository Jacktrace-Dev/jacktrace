package main

import "testing"

// Started by the company's overnight worker (JT-02, junior qwen3:30b). Its "unicode first
// letter" case failed because upperFirst sliced the first BYTE, a real bug, fixed in walk.go.
// Workers may only change tests, so the task went to needs-Claude; the cases are the worker's.
func TestUpperFirst(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"a", "A"},
		{"cable moved", "Cable moved"},
		{"Already upper", "Already upper"},
		{"ünicode", "Ünicode"},
		{"éclair", "Éclair"},
		{"1st jack", "1st jack"},
		{"\xff bad byte", "\xff bad byte"},
	}
	for _, tt := range tests {
		if got := upperFirst(tt.in); got != tt.want {
			t.Errorf("upperFirst(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
