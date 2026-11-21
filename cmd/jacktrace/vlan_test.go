package main

// Written by the company's overnight worker (JT-01, junior qwen3:30b), merged as-is.

import (
	"testing"

	"github.com/jacktrace-dev/jacktrace/internal/walk"
)

func TestWorkerVlanSuffix(t *testing.T) {
	tests := []struct {
		name     string
		row      walk.Row
		expected string
	}{
		{
			name: "VLAN only",
			row: walk.Row{
				VLAN: "42",
			},
			expected: " · VLAN 42",
		},
		{
			name: "VLAN and VoiceVLAN",
			row: walk.Row{
				VLAN:      "42",
				VoiceVLAN: "120",
			},
			expected: " · VLAN 42, voice 120",
		},
		{
			name:     "No VLAN",
			row:      walk.Row{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vlanSuffix(tt.row); got != tt.expected {
				t.Errorf("vlanSuffix() = %q, want %q", got, tt.expected)
			}
		})
	}
}
