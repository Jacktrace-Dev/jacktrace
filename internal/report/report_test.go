package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jacktrace-dev/jacktrace/internal/decode"
	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	tf "github.com/jacktrace-dev/jacktrace/internal/testframes"
)

const eth = "Ethernet (Intel(R) Ethernet Controller (3) I225-V)"

func accessPort(t *testing.T) []discovery.Neighbor {
	t.Helper()
	var out []discovery.Neighbor
	for i, f := range [][]byte{tf.AccessPortLLDP(), tf.AccessPortCDP()} {
		n, err := decode.Frame(f)
		if err != nil {
			t.Fatal(err)
		}
		n.Adapter = eth
		n.Received = time.Date(2026, 10, 23, 9, 0, i, 0, time.UTC)
		out = append(out, n)
	}
	return out
}

func eero() discovery.Neighbor {
	return discovery.Neighbor{
		Protocol: discovery.LLDP, Adapter: "Ethernet", SourceMAC: "02:00:5e:00:00:65",
		SwitchName: "eero", ChassisID: "02:00:5e:00:00:64", SystemDescription: "eero TEST0000000001",
		ManagementIP: "192.0.2.64", PortID: "2", PortDescription: "eth1", Duplex: "full", Media: "1000BASE-T",
	}
}

func TestMergeCDPAndLLDP(t *testing.T) {
	ports := Merge(accessPort(t))
	if len(ports) != 1 {
		t.Fatalf("got %d ports, want CDP and LLDP merged into 1", len(ports))
	}
	p := ports[0]
	checks := map[string][2]string{
		"switch": {p.Switch, "IDF2-ACCESS-01"},
		"model":  {p.Model, "Cisco C9200L-48P-4G"},
		"port":   {p.PortID, "Gi1/0/24"},
		"desc":   {p.Description, "Room 114 desk"},
		"vlans":  {p.VLANs(), "20 data · 120 voice"},
		"mgmt":   {p.ManagementIP, "10.0.20.2"},
		"link":   {p.Link, "1000BASE-T full"},
		"via":    {p.ViaText(), "CDP + LLDP"},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", name, c[0], c[1])
		}
	}
	if p.PoEWatts != 15.4 || !p.Heard.Equal(time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("poe %v heard %v", p.PoEWatts, p.Heard)
	}
}

func TestMergeKeepsAdaptersApart(t *testing.T) {
	a, b := eero(), eero()
	b.Adapter = "Wi-Fi"
	if got := Merge([]discovery.Neighbor{a, b}); len(got) != 2 {
		t.Errorf("got %d ports, want one per adapter", len(got))
	}
}

func TestMergeByNameWhenMACsDiffer(t *testing.T) {
	cdp := discovery.Neighbor{Protocol: discovery.CDP, Adapter: "Ethernet", SourceMAC: "02:00:00:00:00:01", SwitchName: "SW1.corp.example", PortID: "GigabitEthernet0/1"}
	lldp := discovery.Neighbor{Protocol: discovery.LLDP, Adapter: "Ethernet", SourceMAC: "02:00:00:00:00:02", SwitchName: "sw1", PortID: "Gi0/1"}
	got := Merge([]discovery.Neighbor{cdp, lldp})
	if len(got) != 1 || got[0].PortID != "Gi0/1" {
		t.Errorf("got %+v, want one merged port preferring LLDP's port name", got)
	}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	Text(&b, Merge(accessPort(t)), false)
	want := `  switch   IDF2-ACCESS-01  (Cisco C9200L-48P-4G)
  port     Gi1/0/24   "Room 114 desk"
  vlan     20 data · 120 voice
  mgmt     10.0.20.2
  poe      15.4 W
  link     1000BASE-T full
  via      CDP + LLDP on Ethernet (Intel Ethernet Controller (3) I225-V)
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestTextLeavesOutWhatWasntSent(t *testing.T) {
	var b bytes.Buffer
	Text(&b, Merge([]discovery.Neighbor{eero()}), false)
	if strings.Contains(b.String(), "vlan") || strings.Contains(b.String(), "poe") {
		t.Errorf("printed empty fields:\n%s", b.String())
	}
	if !strings.Contains(b.String(), `port     2   "eth1"`) {
		t.Errorf("port line wrong:\n%s", b.String())
	}
}

func TestTicket(t *testing.T) {
	var b bytes.Buffer
	Ticket(&b, Merge(accessPort(t)), "v0.1.0", time.Date(2026, 10, 23, 14, 5, 0, 0, time.UTC))
	want := `Jack trace, 2026-10-23 14:05
Switch:      IDF2-ACCESS-01 (Cisco C9200L-48P-4G)
Port:        Gi1/0/24 ("Room 114 desk")
VLAN:        20 data · 120 voice
Switch IP:   10.0.20.2
PoE:         15.4 W
Link:        1000BASE-T full
Heard via:   CDP + LLDP on Ethernet (Intel Ethernet Controller (3) I225-V)
Tool:        JackTrace v0.1.0
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

func TestBoxIsRectangular(t *testing.T) {
	for _, status := range []string{"listening on Ethernet…", strings.Repeat("x", 80), "heard eero via LLDP · checking for CDP…"} {
		lines := box("v0.1.0", status, 0.4, "0:34 / 2:00", palette(false), "")
		width := utf8.RuneCountInString(lines[0])
		for i, l := range lines {
			if w := utf8.RuneCountInString(l); w != width {
				t.Errorf("status %.20q line %d is %d wide, want %d:\n%s", status, i, w, width, strings.Join(lines, "\n"))
			}
		}
	}
}

func TestLiveWithoutAnimation(t *testing.T) {
	var b bytes.Buffer
	l := NewLive(&b, false, false, "v0.1.0", 2*time.Minute)
	l.Listening([]string{"Ethernet"})
	l.Heard([]discovery.Neighbor{eero()})
	l.Finish(true, false)
	out := b.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape codes without animation/colour: %q", out)
	}
	if strings.Count(out, "┌") != 2 || !strings.Contains(out, "listening on Ethernet…") || !strings.Contains(out, "found it") {
		t.Errorf("want a start box and a final box:\n%s", out)
	}
}

func TestShortLabel(t *testing.T) {
	if got := ShortLabel(eth); got != "Ethernet (Intel Ethernet Controller (3) I225-V)" {
		t.Errorf("got %q", got)
	}
}

func TestWatts(t *testing.T) {
	for in, want := range map[float64]string{15.4: "15.4 W", 30: "30 W", 0.5: "0.5 W"} {
		if got := watts(in); got != want {
			t.Errorf("watts(%v) = %q, want %q", in, got, want)
		}
	}
}
