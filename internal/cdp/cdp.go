// Package cdp decodes Cisco Discovery Protocol (CDP) version 1 and 2 announcements.
package cdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
)

// TLV types.
const (
	tlvDeviceID       = 0x0001
	tlvAddresses      = 0x0002
	tlvPortID         = 0x0003
	tlvCapabilities   = 0x0004
	tlvSoftware       = 0x0005
	tlvPlatform       = 0x0006
	tlvVTPDomain      = 0x0009
	tlvNativeVLAN     = 0x000A
	tlvDuplex         = 0x000B
	tlvVoIPVLANReply  = 0x000E
	tlvMgmtAddresses  = 0x0016
	tlvPowerAvailable = 0x001A
)

// Parse decodes a CDP PDU: the bytes after the LLC/SNAP header (version, TTL, checksum, TLVs).
// The checksum isn't verified; Cisco's handling of odd lengths differs between releases and a
// bad checksum is no reason to hide what the switch said.
// On a cut-off PDU it returns what it decoded so far together with discovery.ErrTruncated.
func Parse(pdu []byte) (discovery.Neighbor, error) {
	n := discovery.Neighbor{Protocol: discovery.CDP}
	if len(pdu) < 4 {
		return n, discovery.ErrTruncated
	}
	if v := pdu[0]; v != 1 && v != 2 {
		return n, fmt.Errorf("cdp: unsupported version %d", v)
	}
	n.TTL = time.Duration(pdu[1]) * time.Second
	pdu = pdu[4:]

	var mgmtIP, addrIP string
	for len(pdu) > 0 {
		if len(pdu) < 4 {
			return n, discovery.ErrTruncated
		}
		typ := binary.BigEndian.Uint16(pdu[0:2])
		length := int(binary.BigEndian.Uint16(pdu[2:4]))
		if length < 4 {
			return n, fmt.Errorf("cdp: TLV 0x%04x has impossible length %d", typ, length)
		}
		if length > len(pdu) {
			return n, discovery.ErrTruncated
		}
		v := pdu[4:length]
		pdu = pdu[length:]

		switch typ {
		case tlvDeviceID:
			n.SwitchName = discovery.CleanText(v)
		case tlvAddresses:
			addrIP = firstIPv4(v)
		case tlvMgmtAddresses:
			mgmtIP = firstIPv4(v)
		case tlvPortID:
			n.PortID = discovery.CleanText(v)
		case tlvCapabilities:
			if len(v) >= 4 {
				n.Capabilities = capabilities(binary.BigEndian.Uint32(v))
			}
		case tlvSoftware:
			n.SoftwareVersion = discovery.CleanText(v)
		case tlvPlatform:
			n.Platform = discovery.CleanText(v)
		case tlvVTPDomain:
			n.VTPDomain = discovery.CleanText(v)
		case tlvNativeVLAN:
			if len(v) >= 2 {
				if vlan := int(binary.BigEndian.Uint16(v)); discovery.ValidVLAN(vlan) {
					n.NativeVLAN = vlan
				}
			}
		case tlvDuplex:
			if len(v) >= 1 {
				n.Duplex = map[byte]string{0: "half", 1: "full"}[v[0]]
			}
		case tlvVoIPVLANReply: // appliance ID(1), VLAN(2)
			if len(v) >= 3 {
				if vlan := int(binary.BigEndian.Uint16(v[1:3])); discovery.ValidVLAN(vlan) {
					n.VoiceVLAN = vlan
				}
			}
		case tlvPowerAvailable: // request ID(2), management ID(2), power available in mW(4), ...
			if len(v) >= 8 {
				if mw := binary.BigEndian.Uint32(v[4:8]); mw > 0 && mw != 0xFFFFFFFF {
					n.PoEWatts = float64(mw) / 1000
				}
			}
		}
	}

	// The management address is the one meant for reaching the switch; fall back to the
	// interface address if the switch doesn't send one.
	n.ManagementIP = mgmtIP
	if n.ManagementIP == "" {
		n.ManagementIP = addrIP
	}
	return n, nil
}

// firstIPv4 walks an address list: count(4), then per address protocol type(1),
// protocol length(1), protocol, address length(2), address. IP is NLPID 0xCC.
func firstIPv4(v []byte) string {
	if len(v) < 4 {
		return ""
	}
	count := binary.BigEndian.Uint32(v)
	v = v[4:]
	for i := uint32(0); i < count; i++ {
		if len(v) < 2 {
			return ""
		}
		protoType, protoLen := v[0], int(v[1])
		if len(v) < 2+protoLen+2 {
			return ""
		}
		proto := v[2 : 2+protoLen]
		addrLen := int(binary.BigEndian.Uint16(v[2+protoLen:]))
		start := 2 + protoLen + 2
		if len(v) < start+addrLen {
			return ""
		}
		addr := v[start : start+addrLen]
		v = v[start+addrLen:]
		if protoType == 1 && protoLen == 1 && proto[0] == 0xCC && addrLen == 4 {
			return net.IP(addr).String()
		}
	}
	return ""
}

var capabilityNames = []struct {
	bit  uint32
	name string
}{
	{0x001, "Router"},
	{0x002, "Transparent bridge"},
	{0x004, "Source-route bridge"},
	{0x008, "Switch"},
	{0x010, "Host"},
	{0x020, "IGMP"},
	{0x040, "Repeater"},
	{0x080, "Phone"},
	{0x100, "Remotely managed"},
	{0x200, "CVTA"},
	{0x400, "Two-port MAC relay"},
}

func capabilities(bits uint32) []string {
	var out []string
	for _, c := range capabilityNames {
		if bits&c.bit != 0 {
			out = append(out, c.name)
		}
	}
	return out
}
