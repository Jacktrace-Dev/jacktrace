package main

import (
	"testing"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/capture"
)

// Written by the company's overnight worker (JT-06, junior qwen3:30b). Review folded five
// copy-pasted test functions into this one table; the cases are the worker's.
func TestWorkerNothingHeard(t *testing.T) {
	const noLink = "No network adapter has a link. Check that the cable is plugged in at both ends and the jack is live."
	const noSwitch = "No switch announced itself in 2 minutes. Likely causes:\n" +
		"  • CDP and LLDP are turned off on that switch or port\n" +
		"  • an unmanaged switch, hub or phone sits between this jack and the switch\n" +
		"  • the jack goes to a router or home mesh unit that doesn't announce itself"
	tests := []struct {
		name     string
		adapters []capture.Adapter
		want     string
	}{
		{"no adapters", []capture.Adapter{}, noLink},
		{"one adapter, down", []capture.Adapter{{Up: false}}, noLink},
		{"one adapter, up", []capture.Adapter{{Up: true}}, noSwitch},
		{"several, all down", []capture.Adapter{{Up: false}, {Up: false}}, noLink},
		{"several, one up", []capture.Adapter{{Up: false}, {Up: true}}, noSwitch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nothingHeard(tt.adapters, 2*time.Minute); got != tt.want {
				t.Errorf("nothingHeard(%s) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
