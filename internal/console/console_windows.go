// Package console smooths over Windows console differences: colour support, elevation, and
// whether JackTrace owns its console window (it was double-clicked).
package console

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode        = kernel32.NewProc("SetConsoleMode")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
)

const enableVirtualTerminalProcessing = 0x0004

// IsTerminal reports whether f is a console (not a pipe or file).
func IsTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}

// EnableANSI turns on escape-code handling for f and reports whether it's available. Windows
// Terminal always has it; the classic console has had it since Windows 10 1511 but needs it
// switched on per process.
func EnableANSI(f *os.File) bool {
	h := syscall.Handle(f.Fd())
	var mode uint32
	if syscall.GetConsoleMode(h, &mode) != nil {
		return false
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return true
	}
	r, _, _ := procSetConsoleMode.Call(uintptr(h), uintptr(mode|enableVirtualTerminalProcessing))
	return r != 0
}

// OwnsConsole reports whether this process is the only one attached to its console window,
// which means it was started by double-clicking (or by UAC, which opens a new window). In that
// case the window closes the moment JackTrace exits, so it should wait for Enter first.
func OwnsConsole() bool {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return n == 1
}

// IsElevated reports whether JackTrace is running as administrator (pktmon requires it).
func IsElevated() bool {
	var token syscall.Token
	if syscall.OpenProcessToken(syscall.Handle(currentProcess()), syscall.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	const tokenElevation = 20
	var elevated, n uint32
	if syscall.GetTokenInformation(token, tokenElevation, (*byte)(unsafe.Pointer(&elevated)), 4, &n) != nil {
		return false
	}
	return elevated != 0
}

func currentProcess() uintptr {
	h, _ := syscall.GetCurrentProcess()
	return uintptr(h)
}
