package capture

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	tf "github.com/jacktrace-dev/jacktrace/internal/testframes"
)

// Shaped like real `pktmon list --json` output from a test PC, with made-up MACs: a NetAdapterCx
// wired NIC (NetCx component below its Miniport), a classic Wi-Fi miniport, a tunnel with no MAC,
// and a filter driver that must not be mistaken for an adapter.
const listJSON = `[
 {"Group":"Intel(R) Ethernet Controller (3) I225-V","Components":[
  {"Name":"Intel(R) Ethernet Controller (3) I225-V","DriverName":"e2fn.sys","Type":"NetCx","Id":118,
   "Properties":[{"Name":"MAC Address","Value":"02-00-00-00-AA-01"},{"Name":"ifIndex","Value":7}]},
  {"Name":"Intel(R) Ethernet Controller (3) I225-V","DriverName":"netadaptercx.sys","Type":"Miniport","Id":13,
   "Properties":[{"Name":"MAC Address","Value":"02-00-00-00-AA-01"},{"Name":"ifIndex","Value":7}]},
  {"Name":"Npcap Packet Driver (NPCAP)","DriverName":"npcap.sys","Type":"Filter","Id":41,
   "Properties":[{"Name":"Miniport ifIndex","Value":7}]}]},
 {"Group":"Intel(R) Wi-Fi 6E AX210 160MHz","Components":[
  {"Name":"Intel(R) Wi-Fi 6E AX210 160MHz","Type":"Miniport","Id":14,
   "Properties":[{"Name":"MAC Address","Value":"02-00-00-00-AA-02"},{"Name":"ifIndex","Value":9}]}]},
 {"Group":"Tailscale Tunnel","Components":[
  {"Name":"Tailscale Tunnel","Type":"Miniport","Id":11,"Properties":[{"Name":"ifIndex","Value":12}]}]}
]`

var ownMAC = net.HardwareAddr{0x02, 0, 0, 0, 0xAA, 0x01}

func fakeLookup(i int) (string, bool, bool) {
	switch i {
	case 7:
		return "Ethernet", true, true
	case 9:
		return "Wi-Fi", false, true
	}
	return "", false, false
}

func TestParseAdapters(t *testing.T) {
	got, err := parseAdapters([]byte(listJSON), fakeLookup)
	if err != nil {
		t.Fatal(err)
	}
	want := []Adapter{
		{ComponentID: 118, Description: "Intel(R) Ethernet Controller (3) I225-V", Name: "Ethernet", MAC: "02:00:00:00:aa:01", IfIndex: 7, Up: true},
		{ComponentID: 14, Description: "Intel(R) Wi-Fi 6E AX210 160MHz", Name: "Wi-Fi", MAC: "02:00:00:00:aa:02", IfIndex: 9},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if got[0].Label() != "Ethernet (Intel(R) Ethernet Controller (3) I225-V)" {
		t.Errorf("label = %q", got[0].Label())
	}
}

func TestParseInbound(t *testing.T) {
	js := `[{"Group":"x","Components":[
	 {"Name":"nic","Id":118,"Counters":[{"Name":"Lower","Type":"Flows","Inbound":{"DirectionTag":"Rx","Packets":2,"Bytes":272},"Outbound":{"Packets":1}}]},
	 {"Name":"nic","Id":13,"Counters":[{"Name":"Upper","Inbound":{"Packets":2}}]}]}]`
	got, err := parseInbound([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if got[118] != 2 || got[13] != 2 {
		t.Errorf("got %v, want Rx from whichever counter each component has", got)
	}
}

// fakePktmon plays back scripted rounds: frames[round][componentID] arrive after `delay` polls.
type fakePktmon struct {
	mu           sync.Mutex
	calls        []string
	busy         bool
	filterList   string
	frames       map[int]map[int][][]byte
	delay        int
	failStart    error
	onCounters   func(round, polls int)
	reverseTimes bool // later packets get earlier timestamps

	round, polls int
	inbound      map[int]uint64
}

func (f *fakePktmon) SessionRunning(context.Context) (bool, error) { return f.busy, nil }

func (f *fakePktmon) Pktmon(ctx context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args[:min(2, len(args))], " "))
	switch args[0] {
	case "filter":
		if args[1] == "list" {
			return []byte(f.filterList), nil
		}
	case "list":
		return []byte(listJSON), nil
	case "start":
		if f.failStart != nil {
			return nil, f.failStart
		}
		f.round++
		f.polls = 0
		if f.inbound == nil {
			f.inbound = map[int]uint64{}
		}
	case "counters":
		f.polls++
		if f.polls > f.delay {
			for id, fr := range f.frames[f.round] {
				f.inbound[id] = uint64(len(fr)) + 100*uint64(f.round)
			}
		}
		if f.onCounters != nil {
			f.onCounters(f.round, f.polls)
		}
		var comps []map[string]any
		for id, n := range f.inbound {
			comps = append(comps, map[string]any{"Id": id, "Counters": []any{
				map[string]any{"Name": "Lower", "Inbound": map[string]any{"Packets": n}}}})
		}
		return json.Marshal([]any{map[string]any{"Group": "g", "Components": comps}})
	case "etl2pcap":
		out, id := args[3], 0
		fmt.Sscan(args[5], &id)
		fr := f.frames[f.round][id]
		if len(fr) == 0 {
			return nil, nil // pktmon writes nothing for an adapter with no packets
		}
		var pkts []tf.Packet
		for i, b := range fr {
			base := int64(1_800_000_000 + 100*f.round) // the clock moves on between rounds
			ts := time.Unix(base+int64(i), 0)
			if f.reverseTimes {
				ts = time.Unix(base-int64(i), 0)
			}
			pkts = append(pkts, tf.Packet{Time: ts, Data: b})
		}
		return nil, os.WriteFile(out, tf.Pcapng(binary.LittleEndian, pkts...), 0o600)
	}
	return nil, nil
}

func (f *fakePktmon) count(call string) int {
	n := 0
	for _, c := range f.calls {
		if c == call {
			n++
		}
	}
	return n
}

func opts(f *fakePktmon, timeout time.Duration, done func([]discovery.Neighbor, time.Duration) bool, t *testing.T) Options {
	return Options{Timeout: timeout, Poll: time.Millisecond, Done: done, runner: f, lookup: fakeLookup, tempDir: t.TempDir(), Logf: t.Logf}
}

func bothProtocols(ns []discovery.Neighbor, _ time.Duration) bool {
	var cdp, lldp bool
	for _, n := range ns {
		cdp = cdp || n.Protocol == discovery.CDP
		lldp = lldp || n.Protocol == discovery.LLDP
	}
	return cdp && lldp
}

func ownLLDP() []byte {
	return tf.LLDPFrame(ownMAC,
		tf.LLDPTLV(1, append([]byte{4}, ownMAC...)),
		tf.LLDPTLV(2, append([]byte{3}, ownMAC...)),
		tf.LLDPTLV(3, []byte{0, 120}))
}

func TestCaptureHearsBothProtocols(t *testing.T) {
	f := &fakePktmon{delay: 2, frames: map[int]map[int][][]byte{
		1: {118: {ownLLDP(), tf.AccessPortLLDP()}},
		2: {118: {tf.AccessPortCDP()}},
	}}
	got, err := Capture(context.Background(), opts(f, 5*time.Second, bothProtocols, t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Protocol != discovery.LLDP || got[1].Protocol != discovery.CDP {
		t.Fatalf("got %+v, want LLDP then CDP (and not the PC's own LLDP)", got)
	}
	for _, n := range got {
		if n.Adapter != "Ethernet (Intel(R) Ethernet Controller (3) I225-V)" || n.Received.IsZero() || n.PortID == "" {
			t.Errorf("incomplete result: %+v", n)
		}
	}
	if f.count("start --capture") != 2 || f.count("stop") != 2 {
		t.Errorf("starts/stops don't pair up: %v", f.calls)
	}
	if f.count("filter add") != 2 || f.calls[len(f.calls)-1] != "filter remove" {
		t.Errorf("filters not added and removed: %v", f.calls)
	}
}

func TestCaptureTimesOutCleanly(t *testing.T) {
	f := &fakePktmon{}
	got, err := Capture(context.Background(), opts(f, 30*time.Millisecond, nil, t))
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v; want nothing and no error", got, err)
	}
	if f.count("stop") != f.count("start --capture") || f.calls[len(f.calls)-1] != "filter remove" {
		t.Errorf("not cleaned up: %v", f.calls)
	}
}

func TestRefusesWhenBusy(t *testing.T) {
	f := &fakePktmon{busy: true}
	if _, err := Capture(context.Background(), opts(f, time.Second, nil, t)); !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v, want ErrBusy", err)
	}
	if len(f.calls) != 0 {
		t.Errorf("touched pktmon anyway: %v", f.calls)
	}
}

func TestRefusesExistingFilters(t *testing.T) {
	f := &fakePktmon{filterList: "Packet Filters:\n     # Name  IP Address\n     - ----  ----------\n     1 mine  10.0.0.1\n"}
	if _, err := Capture(context.Background(), opts(f, time.Second, nil, t)); !errors.Is(err, ErrFiltersInUse) {
		t.Fatalf("err = %v, want ErrFiltersInUse", err)
	}
	if f.count("filter add") != 0 || f.count("filter remove") != 0 {
		t.Errorf("changed someone else's filters: %v", f.calls)
	}
}

func TestEmptyFilterListInAnyLanguage(t *testing.T) {
	for _, out := range []string{"Packet Filters:\n    None\n", "Paketfilter:\n    Keine\n", ""} {
		if filterRow.MatchString(out) {
			t.Errorf("%q read as having filters", out)
		}
	}
}

func TestCtrlCStillCleansUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakePktmon{onCounters: func(round, polls int) {
		if polls == 3 {
			cancel()
		}
	}}
	_, err := Capture(ctx, opts(f, 10*time.Second, nil, t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if f.count("stop") != 1 || f.calls[len(f.calls)-1] != "filter remove" {
		t.Errorf("not cleaned up after Ctrl+C: %v", f.calls)
	}
}

func TestFailedStartDoesNotStopSomeoneElse(t *testing.T) {
	f := &fakePktmon{failStart: errors.New("Packet Monitor is already started")}
	if _, err := Capture(context.Background(), opts(f, time.Second, nil, t)); err == nil {
		t.Fatal("want an error")
	}
	if f.count("stop") != 0 {
		t.Errorf("stopped a capture we didn't start: %v", f.calls)
	}
	if f.calls[len(f.calls)-1] != "filter remove" {
		t.Errorf("our filters were left behind: %v", f.calls)
	}
}

func TestShutdownWithdrawsNeighbor(t *testing.T) {
	shutdown := tf.LLDPFrame(tf.SwitchMAC,
		tf.LLDPTLV(1, append([]byte{4}, tf.SwitchChassisMAC...)),
		tf.LLDPTLV(2, append([]byte{5}, "Gi1/0/24"...)),
		tf.LLDPTLV(3, []byte{0, 0}))
	f := &fakePktmon{delay: 1, frames: map[int]map[int][][]byte{
		1: {118: {tf.AccessPortLLDP()}},
		2: {118: {shutdown}},
	}}
	got, err := Capture(context.Background(), opts(f, 100*time.Millisecond, nil, t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want the withdrawn neighbor gone", got)
	}
}

func TestUnsupportedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	if _, err := Capture(context.Background(), Options{Timeout: time.Second}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("err = %v, want ErrUnsupported", err)
	}
}

func TestResultsInOrderHeard(t *testing.T) {
	// One round where the later announcement comes first in pktmon's file.
	cdp := tf.AccessPortCDP()
	lldp := tf.AccessPortLLDP()
	f := &fakePktmon{delay: 1, frames: map[int]map[int][][]byte{1: {118: {cdp, lldp}}}}
	f.reverseTimes = true
	got, err := Capture(context.Background(), opts(f, 5*time.Second, bothProtocols, t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Protocol != discovery.LLDP || !got[0].Received.Before(got[1].Received) {
		t.Errorf("got %v then %v, want the earlier-heard LLDP first", got[0].Protocol, got[1].Protocol)
	}
}

func TestSettled(t *testing.T) {
	eero := discovery.Neighbor{Protocol: discovery.LLDP, Adapter: "Ethernet", SwitchName: "eero", SystemDescription: "eero TEST0001"}
	ciscoLLDP := discovery.Neighbor{Protocol: discovery.LLDP, Adapter: "Ethernet", SystemDescription: "Cisco IOS Software, C9200L"}
	ciscoCDP := discovery.Neighbor{Protocol: discovery.CDP, Adapter: "Ethernet", Platform: "cisco C9200L-48P-4G"}
	wifiCDP := discovery.Neighbor{Protocol: discovery.CDP, Adapter: "Wi-Fi"}
	s := time.Second
	cases := []struct {
		name  string
		heard []discovery.Neighbor
		at    time.Duration
		want  bool
	}{
		{"nothing yet", nil, 90 * s, false},
		{"non-Cisco LLDP stops at once", []discovery.Neighbor{eero}, 3 * s, true},
		{"Cisco LLDP waits for CDP", []discovery.Neighbor{ciscoLLDP}, 40 * s, false},
		{"Cisco LLDP gives up on CDP at 65 s", []discovery.Neighbor{ciscoLLDP}, 65 * s, true},
		{"CDP waits for LLDP", []discovery.Neighbor{ciscoCDP}, 20 * s, false},
		{"CDP gives up on LLDP at 35 s", []discovery.Neighbor{ciscoCDP}, 35 * s, true},
		{"both heard stops at once", []discovery.Neighbor{ciscoLLDP, ciscoCDP}, 2 * s, true},
		{"every adapter must settle", []discovery.Neighbor{eero, wifiCDP}, 10 * s, false},
		{"…and then it stops", []discovery.Neighbor{eero, wifiCDP}, 36 * s, true},
	}
	for _, c := range cases {
		if got := Settled(c.heard, c.at); got != c.want {
			t.Errorf("%s: Settled = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTimeRuleStopsWithoutNewPackets(t *testing.T) {
	// One CDP announcement, then silence: the rule must end the capture on its own clock
	// (polled while listening), not wait for another packet or the long timeout.
	f := &fakePktmon{delay: 1, frames: map[int]map[int][][]byte{1: {118: {tf.AccessPortCDP()}}}}
	var heardCalls int
	o := opts(f, 10*time.Second, func(ns []discovery.Neighbor, listening time.Duration) bool {
		return listening >= 50*time.Millisecond
	}, t)
	o.OnHeard = func([]discovery.Neighbor) { heardCalls++ }
	began := time.Now()
	got, err := Capture(context.Background(), o)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("took %v; the time rule didn't end the capture", took)
	}
	if heardCalls != 1 {
		t.Errorf("OnHeard called %d times, want 1", heardCalls)
	}
}

func TestAdapterFilter(t *testing.T) {
	f := &fakePktmon{delay: 1, frames: map[int]map[int][][]byte{1: {14: {tf.AccessPortLLDP()}}}}
	o := opts(f, 30*time.Millisecond, nil, t)
	var listening []Adapter
	o.Adapter = func(a Adapter) bool { return a.Name == "Ethernet" }
	o.OnListening = func(as []Adapter) { listening = as }
	got, err := Capture(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(listening) != 1 || listening[0].Name != "Ethernet" || len(got) != 0 {
		t.Errorf("listening on %v, got %v; want only Ethernet and nothing from Wi-Fi", listening, got)
	}

	o.Adapter = func(Adapter) bool { return false }
	if _, err := Capture(context.Background(), o); !errors.Is(err, ErrNoMatchingAdapter) {
		t.Errorf("err = %v, want ErrNoMatchingAdapter", err)
	}
}
