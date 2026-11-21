package capture

// Written by the company's overnight worker (JT-03, junior qwen3:30b, first try), merged as-is.

import (
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "dash separator",
			input:    "02-00-00-00-AA-01",
			expected: "02:00:00:00:aa:01",
		},
		{
			name:     "colon separator",
			input:    "02:00:00:00:AA:01",
			expected: "02:00:00:00:aa:01",
		},
		{
			name:     "no separator",
			input:    "02000000AA01",
			expected: "02:00:00:00:aa:01",
		},
		{
			name:     "whitespace padding",
			input:    " 02-00-00-00-AA-01 ",
			expected: "02:00:00:00:aa:01",
		},
		{
			name:     "invalid hex digit",
			input:    "02-00-00-00-AA-0G",
			expected: "",
		},
		{
			name:     "too short",
			input:    "02-00-00-00-AA",
			expected: "",
		},
		{
			name:     "too long",
			input:    "02-00-00-00-AA-01-FF",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeMAC(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeMAC(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
