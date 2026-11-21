package report

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
)

const (
	boxInner = 44 // characters between "│ " and " │"
	barCells = 18
)

// Live draws the boxed status from BRAND.md and, on an ANSI terminal, redraws it every second:
//
//	┌─ JackTrace v0.1.0 ─────────────────────────┐
//	│ listening on Ethernet (Intel I225-V)…      │
//	│ ██████████░░░░░░░░  0:34 / 2:00            │
//	└────────────────────────────────────────────┘
//
// Without animation (output redirected, NO_COLOR or an old console) it draws the box once at the
// start and once at the end.
type Live struct {
	w       io.Writer
	animate bool
	c       colors
	version string
	total   time.Duration

	mu       sync.Mutex
	start    time.Time
	status   string
	drawn    bool
	stopTick chan struct{}
	ticking  sync.WaitGroup
}

// NewLive prepares the box. animate turns on redrawing (which needs ANSI cursor control).
func NewLive(w io.Writer, animate, color bool, version string, total time.Duration) *Live {
	return &Live{w: w, animate: animate, c: palette(color), version: version, total: total}
}

// Listening is called when capture starts.
func (l *Live) Listening(adapters []string) {
	l.mu.Lock()
	l.start = time.Now()
	l.status = "listening on " + joinAdapters(adapters) + "…"
	l.drawLocked(false)
	l.mu.Unlock()
	if l.animate {
		l.stopTick = make(chan struct{})
		l.ticking.Add(1)
		go l.tick()
	}
}

// Heard updates the status line when announcements arrive but JackTrace is still listening for
// the other protocol.
func (l *Live) Heard(ns []discovery.Neighbor) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var cdp, lldp bool
	name := ""
	for _, n := range ns {
		cdp = cdp || n.Protocol == discovery.CDP
		lldp = lldp || n.Protocol == discovery.LLDP
		if name == "" {
			name = n.SwitchName
		}
	}
	if name == "" {
		name = "a switch"
	}
	switch {
	case cdp && !lldp:
		l.status = "heard " + name + " via CDP · checking for LLDP…"
	case lldp && !cdp:
		l.status = "heard " + name + " via LLDP · checking for CDP…"
	default:
		l.status = "heard " + name + "…"
	}
	if !l.animate {
		return
	}
	l.drawLocked(true)
}

// Finish stops the animation and draws the final box.
func (l *Live) Finish(found bool, interrupted bool) {
	if l.stopTick != nil {
		close(l.stopTick)
		l.ticking.Wait()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.start.IsZero() {
		return // never started listening (preflight failed)
	}
	switch {
	case interrupted:
		l.status = "stopped"
	case found:
		l.status = "found it"
	default:
		l.status = "no switch heard"
	}
	l.drawFinalLocked(found, interrupted)
	if l.animate {
		fmt.Fprint(l.w, "\x1b[?25h") // show the cursor again
	}
}

func (l *Live) tick() {
	defer l.ticking.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-l.stopTick:
			return
		case <-t.C:
			l.mu.Lock()
			l.drawLocked(true)
			l.mu.Unlock()
		}
	}
}

func (l *Live) drawLocked(redraw bool) {
	elapsed := time.Since(l.start)
	frac := float64(elapsed) / float64(l.total)
	l.paintLocked(redraw && l.animate, l.c.wait, l.status, frac, fmt.Sprintf("%s / %s", clock(elapsed), clock(l.total)))
}

func (l *Live) drawFinalLocked(found, interrupted bool) {
	elapsed := time.Since(l.start)
	barColor := l.c.ok
	if !found {
		barColor = l.c.bad
	}
	frac := 1.0
	if interrupted {
		frac = float64(elapsed) / float64(l.total)
	}
	l.paintLocked(l.animate && l.drawn, barColor, l.status, frac, clock(elapsed))
}

func (l *Live) paintLocked(redraw bool, barColor, status string, frac float64, timeText string) {
	lines := box(l.version, status, frac, timeText, l.c, barColor)
	if redraw && l.drawn {
		fmt.Fprintf(l.w, "\x1b[%dA", len(lines)) // back to the top of the box
	}
	if l.animate && !l.drawn {
		fmt.Fprint(l.w, "\x1b[?25l") // hide the cursor while animating
	}
	for _, s := range lines {
		if l.animate {
			fmt.Fprint(l.w, "\r\x1b[2K")
		}
		fmt.Fprintln(l.w, s)
	}
	l.drawn = true
}

// box renders the four box lines.
func box(version, status string, frac float64, timeText string, c colors, barColor string) []string {
	frac = min(max(frac, 0), 1)
	filled := int(frac*barCells + 0.5)
	bar := barColor + strings.Repeat("█", filled) + c.dim + strings.Repeat("░", barCells-filled) + c.reset

	title := "─ JackTrace " + version + " "
	top := "┌" + title + strings.Repeat("─", boxInner+2-utf8.RuneCountInString(title)) + "┐"
	row := func(text string, visible int) string {
		return c.frame + "│" + c.reset + " " + text + strings.Repeat(" ", max(0, boxInner-visible)) + " " + c.frame + "│" + c.reset
	}
	statusText := fit(status, boxInner)
	barText := "  " + timeText
	return []string{
		c.frame + top + c.reset,
		row(statusText, utf8.RuneCountInString(statusText)),
		row(bar+barText, barCells+utf8.RuneCountInString(barText)),
		c.frame + "└" + strings.Repeat("─", boxInner+2) + "┘" + c.reset,
	}
}

// fit cuts s to n runes, ending with "…" if it had to cut.
func fit(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func clock(d time.Duration) string {
	s := int(d.Round(time.Second) / time.Second)
	return fmt.Sprintf("%d:%02d", s/60, s%60)
}

// ShortLabel trims vendor noise from an adapter label for the narrow box:
// "Ethernet (Intel(R) Ethernet Controller (3) I225-V)" → "Ethernet (Intel Ethernet Controller (3) I225-V)".
func ShortLabel(s string) string {
	for _, junk := range []string{"(R)", "(TM)", "(tm)", "®", "™"} {
		s = strings.ReplaceAll(s, junk, "")
	}
	return strings.Join(strings.Fields(s), " ")
}

func joinAdapters(names []string) string {
	switch len(names) {
	case 0:
		return "no adapters"
	case 1:
		return names[0]
	case 2:
		return names[0] + " and " + names[1]
	}
	return fmt.Sprintf("%s and %d more", names[0], len(names)-1)
}
