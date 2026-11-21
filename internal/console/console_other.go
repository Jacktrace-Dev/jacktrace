//go:build !windows

package console

import "os"

// IsTerminal reports whether f is a terminal (not a pipe or file).
func IsTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// EnableANSI reports whether f understands escape codes. Unix terminals do.
func EnableANSI(f *os.File) bool { return IsTerminal(f) }

// OwnsConsole is a Windows concern; elsewhere the terminal outlives the program.
func OwnsConsole() bool { return false }

// IsElevated is a Windows concern; capture itself reports it's unsupported elsewhere.
func IsElevated() bool { return true }
