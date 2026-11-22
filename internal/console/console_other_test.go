//go:build !windows

package console

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStubs(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "plain"))
	if err != nil {
		t.Fatal(err)
	}
	if IsTerminal(f) || EnableANSI(f) {
		t.Error("a regular file must not count as a terminal")
	}
	f.Close()
	if IsTerminal(f) || EnableANSI(f) { // Stat fails on a closed file
		t.Error("a closed file must not count as a terminal")
	}
	if OwnsConsole() {
		t.Error("OwnsConsole() = true, want false off Windows")
	}
	if !IsElevated() {
		t.Error("IsElevated() = false, want true off Windows")
	}
}
