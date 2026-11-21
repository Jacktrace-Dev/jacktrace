package capture

// Written by the company's overnight worker (JT-04, junior qwen3:30b, first try), merged as-is.

import (
	"testing"
)

func TestWorkerLabel(t *testing.T) {
	tests := []struct {
		name     string
		adapter  Adapter
		expected string
	}{
		{
			name: "empty name, non-empty description",
			adapter: Adapter{
				Name:        "",
				Description: "Intel(R) Ethernet Controller",
			},
			expected: "Intel(R) Ethernet Controller",
		},
		{
			name: "non-empty name, non-empty description",
			adapter: Adapter{
				Name:        "Ethernet",
				Description: "Intel(R) Ethernet Controller",
			},
			expected: "Ethernet (Intel(R) Ethernet Controller)",
		},
		{
			name: "empty name, empty description",
			adapter: Adapter{
				Name:        "",
				Description: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.adapter.Label(); got != tt.expected {
				t.Errorf("Label() = %q, want %q", got, tt.expected)
			}
		})
	}
}
