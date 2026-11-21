// Package lldp decodes LLDP announcements (IEEE 802.1AB), including the IEEE 802.1, IEEE 802.3
// and LLDP-MED (TIA-1057) extensions that carry VLAN, link and PoE details.
package lldp

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
)

// TLV types from IEEE 802.1AB.
const (
	tlvEnd          = 0
	tlvChassisID    = 1
	tlvPortID       = 2
	tlvTTL          = 3
	tlvPortDesc     = 4
	tlvSystemName   = 5
	tlvSystemDesc   = 6
	tlvCapabilities = 7
	tlvMgmtAddress  = 8
	tlvOrgSpecific  = 127
)

// Organizationally unique identifiers for the extensions we read.
var (
	oui8021 = [3]byte{0x00, 0x80, 0xC2}
	oui8023 = [3]byte{0x00, 0x12, 0x0F}
	ouiMED  = [3]byte{0x00, 0x12, 0xBB}
)

// Parse decodes an LLDPDU: the Ethernet payload after the 0x88CC EtherType.
// On a cut-off PDU it returns what it decoded so far together with discovery.ErrTruncated.
func Parse(pdu []byte) (discovery.Neighbor, error) {
	n := discovery.Neighbor{Protocol: discovery.LLDP}
	var medPoE, dot3PoE float64
	var sawChassis, sawPort bool

	for len(pdu) > 0 {
		if len(pdu) < 2 {
			return n, discovery.ErrTruncated
		}
		h := binary.BigEndian.Uint16(pdu)
		typ, length := int(h>>9), int(h&0x1FF)
		if 2+length > len(pdu) {
			return n, discovery.ErrTruncated
		}
		v := pdu[2 : 2+length]
		pdu = pdu[2+length:]

		switch typ {
		case tlvEnd:
			pdu = nil
		case tlvChassisID:
			if len(v) >= 2 {
				n.ChassisID = formatID(v[0], v[1:], chassisMAC, chassisNetwork)
				sawChassis = true
			}
		case tlvPortID:
			if len(v) >= 2 {
				n.PortID = formatID(v[0], v[1:], portMAC, portNetwork)
				sawPort = true
			}
		case tlvTTL:
			if len(v) >= 2 {
				n.TTL = time.Duration(binary.BigEndian.Uint16(v)) * time.Second
				n.Shutdown = n.TTL == 0
			}
		case tlvPortDesc:
			n.PortDescription = discovery.CleanText(v)
		case tlvSystemName:
			n.SwitchName = discovery.CleanText(v)
		case tlvSystemDesc:
			n.SystemDescription = discovery.CleanText(v)
		case tlvCapabilities:
			if len(v) >= 4 {
				n.Capabilities = capabilities(binary.BigEndian.Uint16(v[2:4]))
			}
		case tlvMgmtAddress:
			if ip := mgmtAddress(v); ip != "" && (n.ManagementIP == "" || isIPv6(n.ManagementIP) && !isIPv6(ip)) {
				n.ManagementIP = ip // prefer the first IPv4 address
			}
		case tlvOrgSpecific:
			if len(v) >= 4 {
				orgSpecific(&n, [3]byte{v[0], v[1], v[2]}, v[3], v[4:], &medPoE, &dot3PoE)
			}
		}
	}

	switch {
	case dot3PoE > 0:
		n.PoEWatts = dot3PoE
	case medPoE > 0:
		n.PoEWatts = medPoE
	}
	if !sawChassis || !sawPort {
		return n, fmt.Errorf("lldp: missing mandatory chassis or port ID")
	}
	return n, nil
}

// Chassis ID and Port ID subtypes that carry a MAC or a network address. The other subtypes
// (interface name, alias, locally assigned...) are text.
const (
	chassisMAC     = 4
	chassisNetwork = 5
	portMAC        = 3
	portNetwork    = 4
)

func formatID(subtype byte, v []byte, macSub, netSub byte) string {
	switch subtype {
	case macSub:
		return discovery.FormatMAC(v)
	case netSub:
		if ip := networkAddress(v); ip != "" {
			return ip
		}
		return fmt.Sprintf("%x", v)
	}
	return discovery.CleanText(v)
}

// networkAddress decodes an IANA address family byte followed by the address.
func networkAddress(v []byte) string {
	if len(v) < 1 {
		return ""
	}
	switch {
	case v[0] == 1 && len(v) == 5:
		return net.IP(v[1:5]).String()
	case v[0] == 2 && len(v) == 17:
		return net.IP(v[1:17]).String()
	}
	return ""
}

func isIPv6(s string) bool { return strings.Contains(s, ":") }

// mgmtAddress reads the address out of a Management Address TLV:
// string length (covers subtype + address), subtype, address, then interface and OID fields we skip.
func mgmtAddress(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	l := int(v[0])
	if l < 2 || 1+l > len(v) {
		return ""
	}
	return networkAddress(v[1 : 1+l])
}

var capabilityNames = []string{
	"Other", "Repeater", "Bridge", "WLAN AP", "Router", "Telephone",
	"DOCSIS cable device", "Station", "C-VLAN", "S-VLAN", "Two-port MAC relay",
}

// capabilities lists the enabled system capabilities.
func capabilities(enabled uint16) []string {
	var out []string
	for i, name := range capabilityNames {
		if enabled&(1<<i) != 0 {
			out = append(out, name)
		}
	}
	return out
}

func orgSpecific(n *discovery.Neighbor, oui [3]byte, sub byte, v []byte, medPoE, dot3PoE *float64) {
	switch oui {
	case oui8021:
		if sub == 1 && len(v) >= 2 { // Port VLAN ID
			if pvid := int(binary.BigEndian.Uint16(v)); discovery.ValidVLAN(pvid) {
				n.NativeVLAN = pvid
			}
		}
	case oui8023:
		switch sub {
		case 1: // MAC/PHY configuration/status: autoneg(1), advertised(2), operational MAU type(2)
			if len(v) >= 5 {
				n.Media, n.Duplex = mauType(binary.BigEndian.Uint16(v[3:5]))
			}
		case 2: // Power via MDI: support(1), pair(1), class(1); 802.3at adds type/source/priority(1),
			// PD requested power(2) and PSE allocated power(2), both in 0.1 W
			if len(v) >= 8 {
				if w := binary.BigEndian.Uint16(v[6:8]); w > 0 {
					*dot3PoE = float64(w) / 10
				}
			}
		}
	case ouiMED:
		switch sub {
		case 2: // Network Policy: application type(1), then U T X VLAN(12) priority(3) DSCP(6)
			if len(v) >= 4 && v[0] == 1 { // application type 1 = voice
				bits := uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
				unknown := bits&(1<<23) != 0
				vlan := int(bits >> 9 & 0xFFF)
				if !unknown && discovery.ValidVLAN(vlan) {
					n.VoiceVLAN = vlan
				}
			}
		case 4: // Extended Power-via-MDI: type/source/priority(1), power value in 0.1 W(2)
			if len(v) >= 3 {
				if w := binary.BigEndian.Uint16(v[1:3]); w > 0 {
					*medPoE = float64(w) / 10
				}
			}
		}
	}
}

// mauType names the common twisted-pair operational MAU types (RFC 4836) and their duplex.
// Anything else is reported by number rather than guessed.
func mauType(t uint16) (media, duplex string) {
	switch t {
	case 10:
		return "10BASE-T", "half"
	case 11:
		return "10BASE-T", "full"
	case 15:
		return "100BASE-TX", "half"
	case 16:
		return "100BASE-TX", "full"
	case 29:
		return "1000BASE-T", "half"
	case 30:
		return "1000BASE-T", "full"
	case 0:
		return "", ""
	}
	return fmt.Sprintf("MAU type %d", t), ""
}
