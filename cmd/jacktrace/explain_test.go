package main

// Written by the company's overnight worker (JT-05, junior qwen3:30b, first try), merged as-is.

import (
	"errors"
	"testing"

	"github.com/jacktrace-dev/jacktrace/internal/capture"
)

func TestWorkerExplain(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		adapter  string
		expected string
	}{
		{
			name:     "no matching adapter",
			err:      capture.ErrNoMatchingAdapter,
			adapter:  "eth0",
			expected: "No network adapter matches \"eth0\". Run without --adapter to listen on all of them.",
		},
		{
			name:     "unsupported OS",
			err:      capture.ErrUnsupported,
			adapter:  "eth0",
			expected: "JackTrace runs on Windows 10 (1809 or later) and Windows 11.",
		},
		{
			name:     "unknown error",
			err:      errors.New("unknown failure"),
			adapter:  "eth0",
			expected: "unknown failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := explain(tt.err, tt.adapter)
			if got != tt.expected {
				t.Errorf("explain(%q, %q) = %q, want %q", tt.err.Error(), tt.adapter, got, tt.expected)
			}
		})
	}
}
