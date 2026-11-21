// Package report turns decoded announcements into what a tech reads: one entry per switch port,
// with CDP and LLDP from the same port merged.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
)

// Port is everything known about the switch port at the other end of one adapter's cable.
type Port struct {
	Adapter      string
	Switch       string
	Model        string
	PortID       string
	Description  string // the switch's label for the port, e.g. "Room 114 desk"
	NativeVLAN   int
	VoiceVLAN    int
	ManagementIP string
	PoEWatts     float64
	Link         string // e.g. "1000BASE-T full"
	Via          []discovery.Protocol
	Truncated    bool
	Heard        time.Time
}

// Merge groups announcements by adapter and switch port. CDP and LLDP from the same port are
// recognised by their sender MAC or, failing that, by switch name. Where both protocols say
// something, LLDP wins for names and ports (it carries the short port name and the description)
// and CDP wins for the model (its Platform field is cleaner than LLDP's free-text description).
func Merge(ns []discovery.Neighbor) []Port {
	type group struct {
		adapter string
		macs    map[string]bool
		names   map[string]bool
		members []discovery.Neighbor
	}
	var groups []*group
	for _, n := range ns {
		var g *group
		for _, cand := range groups {
			if cand.adapter == n.Adapter && (cand.macs[n.SourceMAC] || cand.names[hostname(n.SwitchName)]) {
				g = cand
				break
			}
		}
		if g == nil {
			g = &group{adapter: n.Adapter, macs: map[string]bool{}, names: map[string]bool{}}
			groups = append(groups, g)
		}
		if n.SourceMAC != "" {
			g.macs[n.SourceMAC] = true
		}
		if h := hostname(n.SwitchName); h != "" {
			g.names[h] = true
		}
		g.members = append(g.members, n)
	}

	var out []Port
	for _, g := range groups {
		var lldp, cdp []discovery.Neighbor
		for _, n := range g.members {
			if n.Protocol == discovery.LLDP {
				lldp = append(lldp, n)
			} else {
				cdp = append(cdp, n)
			}
		}
		pref := append(append([]discovery.Neighbor{}, lldp...), cdp...) // LLDP first
		p := Port{Adapter: g.adapter}
		p.Switch = first(pref, func(n discovery.Neighbor) string { return n.SwitchName })
		if p.Switch == "" {
			p.Switch = first(pref, func(n discovery.Neighbor) string { return n.ChassisID })
		}
		p.Model = first(cdp, func(n discovery.Neighbor) string { return prettyPlatform(n.Platform) })
		if p.Model == "" {
			p.Model = first(lldp, func(n discovery.Neighbor) string { return shorten(n.SystemDescription, 48) })
		}
		p.PortID = first(pref, func(n discovery.Neighbor) string { return n.PortID })
		p.Description = first(lldp, func(n discovery.Neighbor) string { return n.PortDescription })
		if p.Description == p.PortID {
			p.Description = ""
		}
		p.ManagementIP = first(pref, func(n discovery.Neighbor) string { return n.ManagementIP })
		p.Link = first(lldp, func(n discovery.Neighbor) string { return strings.TrimSpace(n.Media + " " + n.Duplex) })
		if p.Link == "" {
			if d := first(cdp, func(n discovery.Neighbor) string { return n.Duplex }); d != "" {
				p.Link = d + " duplex"
			}
		}
		for _, n := range pref {
			if p.NativeVLAN == 0 {
				p.NativeVLAN = n.NativeVLAN
			}
			if p.VoiceVLAN == 0 {
				p.VoiceVLAN = n.VoiceVLAN
			}
			if p.PoEWatts == 0 {
				p.PoEWatts = n.PoEWatts
			}
			p.Truncated = p.Truncated || n.Truncated
			if p.Heard.IsZero() || (!n.Received.IsZero() && n.Received.Before(p.Heard)) {
				p.Heard = n.Received
			}
		}
		if len(cdp) > 0 {
			p.Via = append(p.Via, discovery.CDP)
		}
		if len(lldp) > 0 {
			p.Via = append(p.Via, discovery.LLDP)
		}
		out = append(out, p)
	}
	return out
}

func first(ns []discovery.Neighbor, f func(discovery.Neighbor) string) string {
	for _, n := range ns {
		if v := f(n); v != "" {
			return v
		}
	}
	return ""
}

// hostname lowercases a switch name and drops any domain, so CDP's "sw1.corp.example" and
// LLDP's "SW1" match.
func hostname(s string) string {
	s = strings.ToLower(s)
	if i := strings.IndexByte(s, '.'); i > 0 {
		s = s[:i]
	}
	return s
}

// prettyPlatform turns CDP's "cisco C9200L-48P-4G" into "Cisco C9200L-48P-4G".
func prettyPlatform(s string) string {
	if strings.HasPrefix(s, "cisco ") {
		return "Cisco " + s[len("cisco "):]
	}
	return s
}

// shorten keeps the first line of s and cuts it to max runes with an ellipsis.
func shorten(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	r := []rune(strings.TrimSpace(s))
	if len(r) <= max {
		return string(r)
	}
	return strings.TrimSpace(string(r[:max-1])) + "…"
}

// VLANs renders "20 data · 120 voice", "20", "120 voice", or "".
func (p Port) VLANs() string {
	switch {
	case p.NativeVLAN > 0 && p.VoiceVLAN > 0:
		return fmt.Sprintf("%d data · %d voice", p.NativeVLAN, p.VoiceVLAN)
	case p.NativeVLAN > 0:
		return fmt.Sprint(p.NativeVLAN)
	case p.VoiceVLAN > 0:
		return fmt.Sprintf("%d voice", p.VoiceVLAN)
	}
	return ""
}

// ViaText renders "CDP + LLDP".
func (p Port) ViaText() string {
	var s []string
	for _, v := range p.Via {
		s = append(s, string(v))
	}
	return strings.Join(s, " + ")
}

func watts(w float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.1f", w), "0"), ".") + " W"
}

// Text writes the results block from BRAND.md: lowercase labels in one column, values in another.
func Text(w io.Writer, ports []Port, color bool) {
	c := palette(color)
	for i, p := range ports {
		if i > 0 {
			fmt.Fprintln(w)
		}
		line := func(label, value string) {
			if value != "" {
				fmt.Fprintf(w, "  %s%-8s%s %s%s%s\n", c.dim, label, c.reset, c.value, value, c.reset)
			}
		}
		sw := p.Switch
		if p.Model != "" && !strings.EqualFold(p.Model, p.Switch) {
			sw += "  " + c.reset + c.dim + "(" + p.Model + ")"
		}
		line("switch", sw)
		port := p.PortID
		if p.Description != "" {
			port += "   " + c.reset + "\"" + p.Description + "\""
		}
		line("port", port)
		line("vlan", p.VLANs())
		line("mgmt", p.ManagementIP)
		if p.PoEWatts > 0 {
			line("poe", watts(p.PoEWatts))
		}
		line("link", p.Link)
		line("via", p.ViaText()+c.reset+c.dim+" on "+ShortLabel(p.Adapter))
		if p.Truncated {
			fmt.Fprintf(w, "  %s%-8s some details were cut off by the capture%s\n", c.dim, "note", c.reset)
		}
	}
}

// Ticket writes a plain block to paste into a helpdesk ticket.
func Ticket(w io.Writer, ports []Port, version string, at time.Time) {
	fmt.Fprintf(w, "Jack trace, %s\n", at.Format("2006-01-02 15:04"))
	if len(ports) == 0 {
		fmt.Fprintln(w, "No switch announced itself (no CDP or LLDP heard).")
	}
	for i, p := range ports {
		if i > 0 {
			fmt.Fprintln(w)
		}
		row := func(label, value string) {
			if value != "" {
				fmt.Fprintf(w, "%-12s %s\n", label+":", value)
			}
		}
		sw := p.Switch
		if p.Model != "" && !strings.EqualFold(p.Model, p.Switch) {
			sw += " (" + p.Model + ")"
		}
		row("Switch", sw)
		port := p.PortID
		if p.Description != "" {
			port += " (\"" + p.Description + "\")"
		}
		row("Port", port)
		row("VLAN", p.VLANs())
		row("Switch IP", p.ManagementIP)
		if p.PoEWatts > 0 {
			row("PoE", watts(p.PoEWatts))
		}
		row("Link", p.Link)
		row("Heard via", p.ViaText()+" on "+ShortLabel(p.Adapter))
	}
	fmt.Fprintf(w, "%-12s JackTrace %s\n", "Tool:", version)
}

type colors struct{ dim, value, frame, wait, ok, bad, reset string }

func palette(on bool) colors {
	if !on {
		return colors{}
	}
	// Plain 16-colour ANSI so the user's terminal theme decides the exact shades. BRAND.md maps
	// blue = frame (Cat6), yellow = listening (activity LED), green = found (link LED).
	return colors{dim: "\x1b[2m", value: "\x1b[32m", frame: "\x1b[34m", wait: "\x1b[33m", ok: "\x1b[32m", bad: "\x1b[31m", reset: "\x1b[0m"}
}
