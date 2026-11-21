package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// execRunner runs the real pktmon and logman.
type execRunner struct{}

func (execRunner) Pktmon(ctx context.Context, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, "pktmon", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("pktmon %s: %w: %s", args[0], err, bytes.TrimSpace(out))
	}
	return out, nil
}

// SessionRunning asks Windows' trace-session tool whether the "PktMon" session exists. Unlike
// pktmon's own status text, this doesn't change with the Windows display language: logman exits
// 0 when the session is running and non-zero when it isn't.
func (execRunner) SessionRunning(ctx context.Context) (bool, error) {
	err := exec.CommandContext(ctx, "logman", "query", "PktMon", "-ets").Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit):
		return false, nil
	default:
		return false, err
	}
}
