// Command jacktrace tells you which switch port a network jack is patched to, by listening for
// the CDP and LLDP announcements switches send.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/capture"
	"github.com/jacktrace-dev/jacktrace/internal/console"
	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	"github.com/jacktrace-dev/jacktrace/internal/report"
)

// version is set at release time with -ldflags "-X main.version=v0.1.0".
var version = "dev"

// Exit codes.
const (
	exitFound       = 0
	exitError       = 1
	exitNothing     = 3   // listened the whole time and heard no switch
	exitInterrupted = 130 // Ctrl+C, as shells expect
)

func main() {
	code := run()
	if console.OwnsConsole() {
		// Double-clicked (or launched through UAC): the window vanishes on exit, so wait.
		fmt.Fprint(os.Stderr, "\nPress Enter to close…")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}
	os.Exit(code)
}

func run() int {
	if len(os.Args) > 1 && os.Args[1] == "walk" {
		return runWalk(os.Args[2:])
	}
	return runTrace(os.Args[1:])
}

// runTrace traces the one jack this PC is plugged into.
func runTrace(args []string) int {
	fs := flag.NewFlagSet("jacktrace", flag.ContinueOnError)
	fs.Usage = func() { usage(fs) }
	showVersion := fs.Bool("version", false, "print the version and exit")
	timeout := fs.Duration("timeout", 2*time.Minute, "longest to listen")
	adapter := fs.String("adapter", "", "only listen on adapters whose name, description or MAC contains this")
	asJSON := fs.Bool("json", false, "print every announcement as JSON")
	ticket := fs.Bool("ticket", false, "print a plain block to paste into a ticket")
	verbose := fs.Bool("v", false, "show capture details on stderr")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitFound
		}
		return exitError
	}
	if *showVersion {
		fmt.Println("jacktrace", version)
		return exitFound
	}

	_, noColor := os.LookupEnv("NO_COLOR")
	errANSI := console.EnableANSI(os.Stderr)
	outANSI := console.EnableANSI(os.Stdout)
	ui := ui{color: !noColor && errANSI}

	if !console.IsElevated() {
		ui.needAdmin()
		return exitError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	live := report.NewLive(os.Stderr, errANSI, !noColor && errANSI, version, *timeout)
	var listenedOn []capture.Adapter
	opt := capture.Options{
		Timeout: *timeout,
		Done:    capture.Settled,
		OnListening: func(as []capture.Adapter) {
			listenedOn = as
			live.Listening(upLabels(as))
		},
		OnHeard: live.Heard,
	}
	if *adapter != "" {
		want := strings.ToLower(*adapter)
		opt.Adapter = func(a capture.Adapter) bool {
			return strings.Contains(strings.ToLower(a.Name+" "+a.Description+" "+a.MAC), want)
		}
	}
	if *verbose {
		opt.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "jacktrace: "+format+"\n", args...)
		}
	}

	heard, err := capture.Capture(ctx, opt)
	interrupted := errors.Is(err, context.Canceled)
	live.Finish(len(heard) > 0, interrupted)

	ports := report.Merge(heard)
	switch {
	case *asJSON:
		if heard == nil {
			heard = []discovery.Neighbor{}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(heard)
	case *ticket:
		if len(ports) > 0 || err == nil {
			report.Ticket(os.Stdout, ports, version, time.Now())
		}
	case len(ports) > 0:
		fmt.Fprintln(os.Stdout)
		report.Text(os.Stdout, ports, !noColor && outANSI)
	}

	switch {
	case interrupted:
		return exitInterrupted
	case err != nil:
		ui.fail(explain(err, *adapter))
		return exitError
	case len(ports) == 0:
		ui.hint(nothingHeard(listenedOn, *timeout))
		return exitNothing
	}
	return exitFound
}

// upLabels lists the adapters with a link, or all of them if none report one (the link state
// lookup can fail; better to show something than nothing). With several adapters it uses just
// the connection names ("Ethernet", "Wi-Fi") so they fit in the box.
func upLabels(as []capture.Adapter) []string {
	var up, all []string
	for _, a := range as {
		l := report.ShortLabel(a.Label())
		if len(as) > 1 && a.Name != "" {
			l = a.Name
		}
		all = append(all, l)
		if a.Up {
			up = append(up, l)
		}
	}
	if len(up) == 0 {
		return all
	}
	return up
}

func explain(err error, adapter string) string {
	switch {
	case errors.Is(err, capture.ErrNoMatchingAdapter):
		return fmt.Sprintf("No network adapter matches %q. Run without --adapter to listen on all of them.", adapter)
	case errors.Is(err, capture.ErrUnsupported):
		return "JackTrace runs on Windows 10 (1809 or later) and Windows 11."
	}
	return err.Error()
}

func nothingHeard(as []capture.Adapter, timeout time.Duration) string {
	anyUp := false
	for _, a := range as {
		anyUp = anyUp || a.Up
	}
	if !anyUp {
		return "No network adapter has a link. Check that the cable is plugged in at both ends and the jack is live."
	}
	return fmt.Sprintf("No switch announced itself in %s. Likely causes:\n"+
		"  • CDP and LLDP are turned off on that switch or port\n"+
		"  • an unmanaged switch, hub or phone sits between this jack and the switch\n"+
		"  • the jack goes to a router or home mesh unit that doesn't announce itself", human(timeout))
}

// human renders 2m as "2 minutes" and anything else the way Go does ("45s", "1m30s").
func human(d time.Duration) string {
	switch {
	case d == time.Minute:
		return "1 minute"
	case d > 0 && d%time.Minute == 0:
		return fmt.Sprintf("%d minutes", d/time.Minute)
	}
	return d.String()
}

type ui struct {
	color bool
}

func (u ui) fail(msg string) {
	if u.color {
		fmt.Fprintf(os.Stderr, "\x1b[31mjacktrace:\x1b[0m %s\n", msg)
		return
	}
	fmt.Fprintf(os.Stderr, "jacktrace: %s\n", msg)
}

func (u ui) needAdmin() {
	u.fail("JackTrace needs administrator rights, because Windows' packet capture (pktmon) does.\n" +
		"Right-click jacktrace.exe and choose \"Run as administrator\", or run it from an admin terminal.")
}

func (u ui) hint(msg string) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, msg)
}

func usage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprintf(w, "JackTrace %s: which switch port is this jack? Ask the switch.\n\n", version)
	fmt.Fprintln(w, "Usage: jacktrace [options]")
	fmt.Fprintln(w, "       jacktrace walk [options] [audit.csv]   trace jack after jack into one CSV")
	fmt.Fprintln(w, "Plug into the jack, run JackTrace as administrator, and wait up to a minute or two.")
	fmt.Fprintln(w)
	fs.PrintDefaults()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 found a switch · 3 heard nothing · 1 error · 130 stopped with Ctrl+C")
}
