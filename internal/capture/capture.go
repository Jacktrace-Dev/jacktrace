// Package capture listens for CDP and LLDP announcements using pktmon, the packet capture tool
// built into Windows 10 (1809+) and Windows 11. No driver install is needed.
//
// pktmon's state is system-wide, so Capture is careful: it refuses to start if someone else is
// already capturing or has filters set, and it always stops its capture and removes its filters
// on the way out, including on Ctrl+C.
package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/decode"
	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	"github.com/jacktrace-dev/jacktrace/internal/pcapfile"
)

var (
	// ErrUnsupported means this OS has no pktmon.
	ErrUnsupported = errors.New("capture needs Windows 10 (1809 or later) or Windows 11")
	// ErrBusy means another pktmon capture is running. JackTrace won't interfere with it.
	ErrBusy = errors.New("another pktmon capture is already running; stop it first (pktmon stop)")
	// ErrFiltersInUse means pktmon already has packet filters. Adding ours would change someone
	// else's setup, and removing them afterwards would delete theirs.
	ErrFiltersInUse = errors.New("pktmon already has packet filters set; clear them first (pktmon filter remove)")
	// ErrNoAdapters means pktmon reported no adapters that can receive CDP or LLDP.
	ErrNoAdapters = errors.New("no network adapters to listen on")
	// ErrNoMatchingAdapter means Options.Adapter rejected every adapter.
	ErrNoMatchingAdapter = errors.New("no network adapter matches")
)

// The destination MACs CDP and LLDP are sent to. Filtering on MAC (not EtherType) is the only
// way to catch CDP, which uses 802.3 + SNAP framing rather than an EtherType.
var filters = []struct{ name, mac string }{
	{"JackTrace-LLDP", "01-80-C2-00-00-0E"},
	{"JackTrace-CDP", "01-00-0C-CC-CC-CC"},
}

// Runner runs the system tools Capture depends on. Tests swap in a fake.
type Runner interface {
	// Pktmon runs pktmon with args and returns its combined output.
	Pktmon(ctx context.Context, args ...string) ([]byte, error)
	// SessionRunning reports whether a pktmon capture is active.
	SessionRunning(ctx context.Context) (bool, error)
}

// Options control a capture.
type Options struct {
	// Timeout is the longest to listen. CDP repeats every 60 s and LLDP every 30 s by default,
	// so anything under about 65 s can miss CDP.
	Timeout time.Duration
	// Poll is how often pktmon's counters are checked for new packets. Default 1 s.
	Poll time.Duration
	// Done decides when to stop early. It gets everything heard so far and how long JackTrace has
	// been listening, after each batch of announcements and on every Poll once something has been
	// heard, so time-based rules ("give CDP until 65 s") work. Nil means listen until Timeout.
	// Settled is the rule the command uses.
	Done func(heard []discovery.Neighbor, listening time.Duration) bool
	// Adapter, if set, limits which adapters are listened to.
	Adapter func(Adapter) bool
	// OnListening is called once, when listening starts, with the adapters being listened to.
	OnListening func([]Adapter)
	// OnHeard is called with everything heard so far each time new announcements are decoded.
	OnHeard func([]discovery.Neighbor)
	// Logf receives progress messages. Nil discards them.
	Logf func(format string, args ...any)

	runner  Runner      // nil means the real pktmon
	lookup  ifaceLookup // nil means net.InterfaceByIndex
	tempDir string      // "" means the OS temp dir
}

// Capture listens on every adapter pktmon can see and returns the neighbors it heard,
// newest announcement per adapter, protocol and sender. On Ctrl+C (ctx cancelled) it returns
// what it has along with ctx.Err().
func Capture(ctx context.Context, opt Options) ([]discovery.Neighbor, error) {
	if opt.runner == nil {
		if runtime.GOOS != "windows" {
			return nil, ErrUnsupported
		}
		opt.runner = execRunner{}
	}
	if opt.lookup == nil {
		opt.lookup = netLookup
	}
	if opt.Poll <= 0 {
		opt.Poll = time.Second
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	s := &session{opt: opt, r: opt.runner, found: map[neighborKey]discovery.Neighbor{}, first: map[neighborKey]time.Time{}}
	return s.run(ctx)
}

type neighborKey struct {
	adapter  string
	protocol discovery.Protocol
	source   string
}

type session struct {
	opt      Options
	r        Runner
	adapters []Adapter
	ownMACs  map[string]bool
	dir      string
	found    map[neighborKey]discovery.Neighbor
	heard    int                       // announcements accepted so far; lets run() tell when something new arrived
	first    map[neighborKey]time.Time // when each neighbor was first heard
}

var filterRow = regexp.MustCompile(`(?m)^\s*\d+\s+\S`)

func (s *session) run(ctx context.Context) (result []discovery.Neighbor, err error) {
	// Preflight: never touch a pktmon setup that isn't ours.
	busy, err := s.r.SessionRunning(ctx)
	if err != nil {
		return nil, fmt.Errorf("checking for a running pktmon capture: %w", err)
	}
	if busy {
		return nil, ErrBusy
	}
	out, err := s.r.Pktmon(ctx, "filter", "list")
	if err != nil {
		return nil, err
	}
	if filterRow.Match(out) {
		return nil, ErrFiltersInUse
	}

	js, err := s.r.Pktmon(ctx, "list", "--json")
	if err != nil {
		return nil, err
	}
	if s.adapters, err = parseAdapters(js, s.opt.lookup); err != nil {
		return nil, err
	}
	if len(s.adapters) == 0 {
		return nil, ErrNoAdapters
	}
	// Every local MAC counts as "this PC", including adapters we're not listening to.
	s.ownMACs = map[string]bool{}
	for _, a := range s.adapters {
		s.ownMACs[a.MAC] = true
	}
	if s.opt.Adapter != nil {
		var keep []Adapter
		for _, a := range s.adapters {
			if s.opt.Adapter(a) {
				keep = append(keep, a)
			}
		}
		if len(keep) == 0 {
			return nil, ErrNoMatchingAdapter
		}
		s.adapters = keep
	}
	for _, a := range s.adapters {
		s.opt.Logf("adapter %d: %s %s up=%v", a.ComponentID, a.Label(), a.MAC, a.Up)
	}

	if s.dir, err = os.MkdirTemp(s.opt.tempDir, "jacktrace-"); err != nil {
		return nil, err
	}
	defer os.RemoveAll(s.dir)

	// From here on, whatever happens, put pktmon back the way we found it. The cleanup gets
	// its own context so a cancelled ctx (Ctrl+C) can't skip it.
	var addedFilters, started bool
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if started {
			if _, e := s.r.Pktmon(cctx, "stop"); e != nil && err == nil {
				err = fmt.Errorf("stopping pktmon: %w", e)
			}
		}
		if addedFilters {
			if _, e := s.r.Pktmon(cctx, "filter", "remove"); e != nil && err == nil {
				err = fmt.Errorf("removing JackTrace's pktmon filters: %w", e)
			}
		}
	}()

	for _, f := range filters {
		addedFilters = true // set before the call: a half-applied add still needs removing
		if _, err := s.r.Pktmon(ctx, "filter", "add", f.name, "-m", f.mac); err != nil {
			return nil, err
		}
	}

	var start time.Time
	deadline := time.Now().Add(s.opt.Timeout)
	done := func() bool {
		return s.opt.Done != nil && len(s.found) > 0 && s.opt.Done(s.results(), time.Since(start))
	}
	for round := 1; ; round++ {
		etl := filepath.Join(s.dir, fmt.Sprintf("round%d.etl", round))
		// Only mark it started once start succeeds: if another capture began since the preflight,
		// our start fails and the cleanup must not stop theirs.
		if _, err := s.r.Pktmon(ctx, "start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", etl); err != nil {
			return s.results(), err
		}
		started = true
		if round == 1 {
			start = time.Now()
			deadline = start.Add(s.opt.Timeout)
			if s.opt.OnListening != nil {
				s.opt.OnListening(s.adapters)
			}
		}
		s.opt.Logf("round %d: listening", round)

		waitErr := s.waitForPackets(ctx, deadline, done)

		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, stopErr := s.r.Pktmon(stopCtx, "stop")
		cancel()
		if stopErr != nil {
			return s.results(), fmt.Errorf("stopping pktmon: %w", stopErr)
		}
		started = false

		heardBefore := s.heard
		if err := s.collect(etl); err != nil {
			return s.results(), err
		}
		if s.heard != heardBefore && s.opt.OnHeard != nil {
			s.opt.OnHeard(s.results())
		}
		if waitErr != nil {
			return s.results(), waitErr
		}
		if done() {
			return s.results(), nil
		}
		if !time.Now().Before(deadline) {
			return s.results(), nil
		}
	}
}

// waitForPackets returns when an adapter receives a filtered packet, when stopNow says what's
// already been heard is enough, at the deadline (nil), or when ctx ends (ctx.Err()). Errors
// reading counters are logged and polling carries on: the capture itself is still running and
// the deadline still applies.
func (s *session) waitForPackets(ctx context.Context, deadline time.Time, stopNow func() bool) error {
	base := s.inbound(ctx)
	t := time.NewTicker(s.opt.Poll)
	defer t.Stop()
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil
		}
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-t.C:
			timer.Stop()
			if stopNow() {
				return nil
			}
			now := s.inbound(ctx)
			for _, a := range s.adapters {
				if now[a.ComponentID] > base[a.ComponentID] {
					s.opt.Logf("packet on %s", a.Label())
					return nil
				}
			}
		}
	}
}

func (s *session) inbound(ctx context.Context) map[int]uint64 {
	js, err := s.r.Pktmon(ctx, "counters", "--json")
	if err != nil {
		s.opt.Logf("reading counters: %v", err)
		return nil
	}
	m, err := parseInbound(js)
	if err != nil {
		s.opt.Logf("%v", err)
	}
	return m
}

// collect converts one round's capture per adapter (which also drops pktmon's duplicate copy of
// each packet from the adapter's upper layer) and decodes it.
func (s *session) collect(etl string) error {
	for _, a := range s.adapters {
		pcap := fmt.Sprintf("%s-%d.pcapng", etl[:len(etl)-len(".etl")], a.ComponentID)
		if _, err := s.r.Pktmon(context.Background(), "etl2pcap", etl, "--out", pcap, "--component-id", fmt.Sprint(a.ComponentID)); err != nil {
			return fmt.Errorf("converting the capture for %s: %w", a.Label(), err)
		}
		f, err := os.Open(pcap)
		if errors.Is(err, os.ErrNotExist) {
			continue // nothing captured on this adapter
		}
		if err != nil {
			return err
		}
		pkts, err := pcapfile.ReadAll(f)
		f.Close()
		if err != nil && len(pkts) == 0 {
			s.opt.Logf("reading %s: %v", filepath.Base(pcap), err)
			continue
		}
		for _, p := range pkts {
			s.add(a, p)
		}
	}
	return nil
}

func (s *session) add(a Adapter, p pcapfile.Packet) {
	n, err := decode.Frame(p.Data)
	if errors.Is(err, decode.ErrNotDiscovery) {
		return
	}
	if s.ownMACs[n.SourceMAC] {
		return // Windows' own LLDP driver announcing this PC, not the switch
	}
	if err != nil && !errors.Is(err, discovery.ErrTruncated) {
		s.opt.Logf("skipping a malformed %s announcement on %s: %v", n.Protocol, a.Label(), err)
		return
	}
	n.Truncated = errors.Is(err, discovery.ErrTruncated)
	n.Adapter = a.Label()
	n.Received = p.Time

	k := neighborKey{n.Adapter, n.Protocol, n.SourceMAC}
	if n.Shutdown {
		delete(s.found, k)
		s.heard++
		return
	}
	if _, seen := s.first[k]; !seen {
		s.first[k] = n.Received
	}
	s.found[k] = n
	s.heard++
}

// results lists neighbors in the order they were first heard. Within one round pktmon's file
// isn't strictly in time order, so this sorts rather than trusting arrival order.
func (s *session) results() []discovery.Neighbor {
	out := make([]discovery.Neighbor, 0, len(s.found))
	for _, n := range s.found {
		out = append(out, n)
	}
	key := func(n discovery.Neighbor) neighborKey { return neighborKey{n.Adapter, n.Protocol, n.SourceMAC} }
	sort.SliceStable(out, func(i, j int) bool {
		fi, fj := s.first[key(out[i])], s.first[key(out[j])]
		if !fi.Equal(fj) {
			return fi.Before(fj)
		}
		return key(out[i]).source < key(out[j]).source
	})
	return out
}
