package capture

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// Adapter is a network adapter pktmon can capture on.
type Adapter struct {
	ComponentID int    // pktmon's ID for the adapter's miniport (lowest layer)
	Description string // driver description, e.g. "Intel(R) Ethernet Controller (3) I225-V"
	Name        string // Windows connection name, e.g. "Ethernet"; empty if unknown
	MAC         string // aa:bb:cc:dd:ee:ff
	IfIndex     int
	Up          bool
}

// Label is how an adapter is shown to people: "Ethernet (Intel(R) Ethernet Controller (3) I225-V)".
func (a Adapter) Label() string {
	if a.Name == "" {
		return a.Description
	}
	return a.Name + " (" + a.Description + ")"
}

// ifaceLookup returns the Windows connection name and link state for an interface index.
type ifaceLookup func(ifIndex int) (name string, up bool, ok bool)

func netLookup(ifIndex int) (string, bool, bool) {
	ifc, err := net.InterfaceByIndex(ifIndex)
	if err != nil {
		return "", false, false
	}
	return ifc.Name, ifc.Flags&net.FlagUp != 0 && ifc.Flags&net.FlagRunning != 0, true
}

// pktmon list --json
type listGroup struct {
	Group      string
	Components []struct {
		Name       string
		Type       string
		Id         int
		Properties []struct {
			Name  string
			Value json.RawMessage
		}
	}
}

// parseAdapters turns `pktmon list --json` into adapters, one per network card that has a MAC
// address. For each card it picks the lowest layer pktmon can see, so every packet is counted and
// converted exactly once: the "NetCx" component on newer NetAdapterCx drivers (which sits below the
// miniport), otherwise the "Miniport". Virtual adapters without a MAC (Tailscale and other
// tunnels) can't receive CDP or LLDP and are skipped.
func parseAdapters(js []byte, lookup ifaceLookup) ([]Adapter, error) {
	var groups []listGroup
	if err := json.Unmarshal(js, &groups); err != nil {
		return nil, fmt.Errorf("reading pktmon's adapter list: %w", err)
	}
	rank := map[string]int{"NetCx": 2, "Miniport": 1}
	var out []Adapter
	for _, g := range groups {
		best := map[string]Adapter{} // by MAC
		bestRank := map[string]int{}
		var order []string
		for _, c := range g.Components {
			r := rank[c.Type]
			if r == 0 {
				continue
			}
			a := Adapter{ComponentID: c.Id, Description: c.Name}
			for _, p := range c.Properties {
				switch p.Name {
				case "MAC Address":
					var s string
					if json.Unmarshal(p.Value, &s) == nil {
						a.MAC = normalizeMAC(s)
					}
				case "ifIndex":
					json.Unmarshal(p.Value, &a.IfIndex)
				}
			}
			if a.MAC == "" {
				continue
			}
			if _, seen := bestRank[a.MAC]; !seen {
				order = append(order, a.MAC)
			}
			if r > bestRank[a.MAC] {
				best[a.MAC], bestRank[a.MAC] = a, r
			}
		}
		for _, mac := range order {
			a := best[mac]
			if lookup != nil && a.IfIndex > 0 {
				a.Name, a.Up, _ = lookup(a.IfIndex)
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// normalizeMAC turns pktmon's "BC-09-1B-0F-17-47" into "bc:09:1b:0f:17:47".
func normalizeMAC(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "-", ":")
	// Older Go releases' ParseMAC reject a bare "02000000AA01", so add the colons ourselves.
	if len(s) == 12 && !strings.Contains(s, ":") {
		s = s[0:2] + ":" + s[2:4] + ":" + s[4:6] + ":" + s[6:8] + ":" + s[8:10] + ":" + s[10:12]
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		return ""
	}
	return hw.String()
}

// pktmon counters --json
type counterGroup struct {
	Components []struct {
		Id       int
		Counters []struct {
			Name    string
			Inbound struct {
				Packets uint64
			}
		}
	}
}

// parseInbound returns packets received by each component, by component ID. A NetCx component
// reports a "Lower" counter and a plain miniport an "Upper" one; components that report both
// (filter drivers) count the same packets twice, so the larger of the two is used.
func parseInbound(js []byte) (map[int]uint64, error) {
	var groups []counterGroup
	if err := json.Unmarshal(js, &groups); err != nil {
		return nil, fmt.Errorf("reading pktmon's counters: %w", err)
	}
	out := map[int]uint64{}
	for _, g := range groups {
		for _, c := range g.Components {
			for _, ctr := range c.Counters {
				out[c.Id] = max(out[c.Id], ctr.Inbound.Packets)
			}
		}
	}
	return out, nil
}
