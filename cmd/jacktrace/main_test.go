package main

import (
	"testing"
	"time"
)

func TestHuman(t *testing.T) {
	for d, want := range map[time.Duration]string{
		2 * time.Minute:  "2 minutes",
		time.Minute:      "1 minute",
		30 * time.Second: "30s",
		90 * time.Second: "1m30s",
	} {
		if got := human(d); got != want {
			t.Errorf("human(%v) = %q, want %q", d, got, want)
		}
	}
}
