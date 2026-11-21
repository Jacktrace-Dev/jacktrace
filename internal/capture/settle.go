package capture

import (
	"strings"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
)

// How long to keep listening for the other protocol once one has been heard. Switches repeat
// CDP every 60 s and LLDP every 30 s by default, so these cover one full interval plus slack,
// counted from when listening started.
const (
	waitForCDP  = 65 * time.Second
	waitForLLDP = 35 * time.Second
)

// Settled is the default stop rule. JackTrace stops as soon as every adapter that has heard a
// switch has heard everything that switch is likely to send:
//
//   - both CDP and LLDP: done;
//   - LLDP from something that isn't Cisco: done, because only Cisco gear sends CDP;
//   - LLDP from Cisco: wait until 65 s in, in case CDP is on too;
//   - CDP only: wait until 35 s in, in case LLDP is on too.
//
// Adapters that have heard nothing don't hold things up (a disconnected Wi-Fi card never will).
func Settled(heard []discovery.Neighbor, listening time.Duration) bool {
	type seen struct{ cdp, lldp, ciscoLLDP bool }
	byAdapter := map[string]*seen{}
	for _, n := range heard {
		a := byAdapter[n.Adapter]
		if a == nil {
			a = &seen{}
			byAdapter[n.Adapter] = a
		}
		switch n.Protocol {
		case discovery.CDP:
			a.cdp = true
		case discovery.LLDP:
			a.lldp = true
			a.ciscoLLDP = a.ciscoLLDP || looksCisco(n)
		}
	}
	if len(byAdapter) == 0 {
		return false
	}
	for _, a := range byAdapter {
		switch {
		case a.cdp && a.lldp:
		case a.lldp && !a.ciscoLLDP:
		case a.lldp && listening >= waitForCDP:
		case a.cdp && listening >= waitForLLDP:
		default:
			return false
		}
	}
	return true
}

func looksCisco(n discovery.Neighbor) bool {
	s := strings.ToLower(n.SystemDescription + " " + n.SwitchName + " " + n.Platform)
	return strings.Contains(s, "cisco") || strings.Contains(s, "meraki")
}
