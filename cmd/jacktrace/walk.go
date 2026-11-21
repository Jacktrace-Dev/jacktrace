package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jacktrace-dev/jacktrace/internal/capture"
	"github.com/jacktrace-dev/jacktrace/internal/console"
	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	"github.com/jacktrace-dev/jacktrace/internal/report"
	"github.com/jacktrace-dev/jacktrace/internal/walk"
)

// runWalk is walk mode: trace jack after jack into one CSV.
func runWalk(args []string) int {
	fs := flag.NewFlagSet("jacktrace walk", flag.ContinueOnError)
	timeout := fs.Duration("timeout", 2*time.Minute, "longest to listen at each jack")
	adapter := fs.String("adapter", "", "only listen on adapters whose name, description or MAC contains this")
	verbose := fs.Bool("v", false, "show capture details")
	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintln(w, "Usage: jacktrace walk [options] [audit.csv]")
		fmt.Fprintln(w, "Trace jack after jack into one CSV. Run it again with the same file to carry on.")
		fmt.Fprintln(w)
		fs.PrintDefaults()
	}
	// Allow the file name before or after the options.
	if err := fs.Parse(args); err != nil {
		return flagExit(err)
	}
	path := ""
	if fs.NArg() > 0 {
		path = fs.Arg(0)
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return flagExit(err)
		}
	}
	if path == "" {
		path = "jacktrace-walk-" + time.Now().Format("2006-01-02") + ".csv"
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}

	_, noColor := os.LookupEnv("NO_COLOR")
	errANSI := console.EnableANSI(os.Stderr)
	u := ui{color: !noColor && errANSI}
	if !console.IsElevated() {
		u.needAdmin()
		return exitError
	}

	audit, err := walk.Open(path)
	if err != nil {
		u.fail(err.Error())
		return exitError
	}

	opt := capture.Options{Timeout: *timeout, Done: capture.Settled}
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
	w := &walker{
		in:      bufio.NewReader(os.Stdin),
		out:     os.Stderr,
		audit:   audit,
		opt:     opt,
		capture: capture.Capture,
		newLive: func() *report.Live {
			return report.NewLive(os.Stderr, errANSI, !noColor && errANSI, version, *timeout)
		},
		color: !noColor && errANSI,
		now:   time.Now,
		notify: func(ctx context.Context) (context.Context, context.CancelFunc) {
			return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		},
	}
	return w.run()
}

func flagExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return exitFound
	}
	return exitError
}

// walker runs the walk loop. Everything it touches from outside is a field, so tests can drive it.
type walker struct {
	in      *bufio.Reader
	out     io.Writer
	audit   *walk.Audit
	opt     capture.Options
	capture func(context.Context, capture.Options) ([]discovery.Neighbor, error)
	newLive func() *report.Live
	color   bool
	now     func() time.Time
	notify  func(context.Context) (context.Context, context.CancelFunc)

	unsaved bool // the last save failed (file open in Excel?); try again after the next jack
}

func (w *walker) run() int {
	c := w.palette()
	fmt.Fprintf(w.out, "%sJackTrace walk mode%s → %s\n", c.title, c.reset, w.audit.Path)
	if n := w.audit.Jacks(); n > 0 {
		fmt.Fprintf(w.out, "Carrying on: %d jack%s already recorded, last was %s.\n", n, plural(n), w.audit.Last())
	}
	fmt.Fprintln(w.out, "Plug into a jack, type its label, press Enter. Type q when you're done.")

	last := w.audit.Last()
	for {
		label, quit := w.ask(last)
		if quit {
			return w.finish()
		}
		code, stop := w.trace(label)
		if stop {
			w.save()
			return code
		}
		last = label
	}
}

// ask prompts for the next label. Enter takes the suggestion, r redoes the last jack, q quits.
func (w *walker) ask(last string) (label string, quit bool) {
	c := w.palette()
	for {
		suggest := walk.NextLabel(last)
		fmt.Fprintln(w.out)
		switch {
		case suggest != "" && last != "":
			fmt.Fprintf(w.out, "Jack label %s[Enter = %s, r = redo %s, q = done]%s: ", c.dim, suggest, last, c.reset)
		case last != "":
			fmt.Fprintf(w.out, "Jack label %s[r = redo %s, q = done]%s: ", c.dim, last, c.reset)
		default:
			fmt.Fprintf(w.out, "Jack label %s[q = done]%s: ", c.dim, c.reset)
		}
		line, err := w.in.ReadString('\n')
		line = strings.TrimSpace(line)
		if err != nil && line == "" {
			fmt.Fprintln(w.out)
			return "", true // input closed: treat as done
		}
		switch strings.ToLower(line) {
		case "q", "quit", "done", "exit":
			return "", true
		case "":
			if suggest == "" {
				fmt.Fprintln(w.out, "Type a label for this jack (whatever's printed on the faceplate).")
				continue
			}
			return suggest, false
		case "r", "redo":
			if last == "" {
				fmt.Fprintln(w.out, "Nothing to redo yet.")
				continue
			}
			return last, false
		}
		return line, false
	}
}

// trace listens at one jack and records the result. stop means end the walk with code.
func (w *walker) trace(label string) (code int, stop bool) {
	c := w.palette()
	for _, r := range w.audit.Rows {
		if r.Jack == label {
			fmt.Fprintf(w.out, "%s is already recorded; this replaces it.\n", label)
			break
		}
	}

	live := w.newLive()
	opt := w.opt
	opt.OnListening = func(as []capture.Adapter) { live.Listening(upLabels(as)) }
	opt.OnHeard = live.Heard
	ctx, cancel := w.notify(context.Background())
	heard, err := w.capture(ctx, opt)
	cancel()
	interrupted := errors.Is(err, context.Canceled)
	live.Finish(len(heard) > 0, interrupted)

	switch {
	case interrupted:
		fmt.Fprintf(w.out, "Stopped. %s wasn't recorded; everything before it is saved.\n", label)
		return exitInterrupted, true
	case err != nil:
		w.uiFail(explain(err, ""))
		return exitError, true
	}

	at := w.now()
	ports := report.Merge(heard)
	if len(ports) == 0 {
		w.audit.Put(label, walk.Nothing(label, at))
		fmt.Fprintf(w.out, "%s✗ %s%s: no switch heard (recorded; type r to try it again)\n", c.bad, label, c.reset)
	} else {
		var rows []walk.Row
		for _, p := range ports {
			row := walk.FromPort(label, p, at)
			if dup, ok := w.audit.Duplicate(row); ok {
				row.Note = "same port as " + dup
			}
			rows = append(rows, row)
		}
		w.audit.Put(label, rows...)
		for _, row := range rows {
			fmt.Fprintf(w.out, "%s✓ %s%s → %s %s%s\n", c.ok, label, c.reset, row.Switch, row.Port, vlanSuffix(row))
			if row.Note != "" {
				fmt.Fprintf(w.out, "  %s⚠ %s. Did the cable move? Is the jack mislabeled?%s\n", c.warn, upperFirst(row.Note), c.reset)
			}
		}
	}
	w.save()
	return 0, false
}

func vlanSuffix(r walk.Row) string {
	switch {
	case r.VLAN != "" && r.VoiceVLAN != "":
		return " · VLAN " + r.VLAN + ", voice " + r.VoiceVLAN
	case r.VLAN != "":
		return " · VLAN " + r.VLAN
	}
	return ""
}

func (w *walker) save() {
	if err := w.audit.Save(); err != nil {
		w.unsaved = true
		fmt.Fprintf(w.out, "%sCouldn't save %s: %v%s\n", w.palette().bad, filepath.Base(w.audit.Path), err, w.palette().reset)
		fmt.Fprintln(w.out, "If it's open in Excel, close it. Nothing is lost: I'll save again after the next jack.")
		return
	}
	if w.unsaved {
		fmt.Fprintf(w.out, "Saved %s.\n", filepath.Base(w.audit.Path))
	}
	w.unsaved = false
}

// finish saves (insisting if the file is locked) and prints a summary.
func (w *walker) finish() int {
	for {
		err := w.audit.Save()
		if err == nil {
			break
		}
		fmt.Fprintf(w.out, "Couldn't save %s: %v\n", filepath.Base(w.audit.Path), err)
		fmt.Fprint(w.out, "Close it in Excel and press Enter to try again (or type q to quit without saving): ")
		line, rerr := w.in.ReadString('\n')
		if strings.EqualFold(strings.TrimSpace(line), "q") || (rerr != nil && line == "") {
			return exitError
		}
	}
	// Count over the whole file, not just this session, so a resumed walk reports everything.
	found, nothing, dups := 0, 0, 0
	seen := map[string]bool{}
	for _, r := range w.audit.Rows {
		if seen[r.Jack] {
			continue
		}
		seen[r.Jack] = true
		if r.Status == walk.StatusFound {
			found++
		} else {
			nothing++
		}
		if strings.HasPrefix(r.Note, "same port as ") {
			dups++
		}
	}
	total := found + nothing
	fmt.Fprintf(w.out, "\n%d jack%s in %s: %d found, %d with no answer", total, plural(total), w.audit.Path, found, nothing)
	if dups > 0 {
		fmt.Fprintf(w.out, ", %d on a port already recorded (see the note column)", dups)
	}
	fmt.Fprintln(w.out, ".")
	return exitFound
}

func (w *walker) uiFail(msg string) { ui{color: w.color}.fail(msg) }

type walkColors struct{ title, dim, ok, bad, warn, reset string }

func (w *walker) palette() walkColors {
	if !w.color {
		return walkColors{}
	}
	return walkColors{title: "\x1b[34m", dim: "\x1b[2m", ok: "\x1b[32m", bad: "\x1b[31m", warn: "\x1b[33m", reset: "\x1b[0m"}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// upperFirst capitalises the first letter. It works on the first rune, not the first byte,
// so "über" becomes "Über" instead of a split, garbled character (JT-02 found this).
func upperFirst(s string) string {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return s
	}
	return string(unicode.ToUpper(r)) + s[size:]
}
