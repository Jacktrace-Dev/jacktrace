// Package decode recognizes CDP and LLDP announcements inside raw Ethernet frames and hands
// them to the right decoder.
package decode

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/jacktrace-dev/jacktrace/internal/cdp"
	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	"github.com/jacktrace-dev/jacktrace/internal/lldp"
)

// ErrNotDiscovery means the frame is neither CDP nor LLDP. Callers skip these.
var ErrNotDiscovery = errors.New("not a CDP or LLDP frame")

const (
	etherTypeLLDP = 0x88CC
	etherTypeVLAN = 0x8100 // 802.1Q tag
	etherTypeQinQ = 0x88A8 // 802.1ad outer tag
)

// cdpSNAP is the 802.2 LLC/SNAP header in front of every CDP PDU:
// DSAP 0xAA, SSAP 0xAA, control 0x03, Cisco OUI 00:00:0C, protocol ID 0x2000.
var cdpSNAP = []byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00}

// Frame decodes one Ethernet frame. It returns ErrNotDiscovery for anything that isn't CDP or LLDP,
// and passes through decoder errors such as discovery.ErrTruncated along with the partial Neighbor.
func Frame(frame []byte) (discovery.Neighbor, error) {
	if len(frame) < 14 {
		return discovery.Neighbor{}, ErrNotDiscovery
	}
	src := discovery.FormatMAC(frame[6:12])
	rest := frame[12:]

	// Skip any VLAN tags. A tagged frame still tells us the right port.
	for len(rest) >= 6 {
		t := binary.BigEndian.Uint16(rest)
		if t != etherTypeVLAN && t != etherTypeQinQ {
			break
		}
		rest = rest[4:]
	}
	if len(rest) < 2 {
		return discovery.Neighbor{}, ErrNotDiscovery
	}
	typeOrLen := int(binary.BigEndian.Uint16(rest))
	payload := rest[2:]

	var (
		n   discovery.Neighbor
		err error
	)
	switch {
	case typeOrLen == etherTypeLLDP:
		n, err = lldp.Parse(payload)
	case typeOrLen <= 1500 && typeOrLen >= len(cdpSNAP) && bytes.HasPrefix(payload, cdpSNAP):
		// 802.3 framing: the length covers LLC/SNAP + PDU. Trim the minimum-size padding,
		// but if the capture cut the frame short, keep what we have and let the decoder say so.
		if typeOrLen < len(payload) {
			payload = payload[:typeOrLen]
		}
		n, err = cdp.Parse(payload[len(cdpSNAP):])
	default:
		return discovery.Neighbor{}, ErrNotDiscovery
	}
	n.SourceMAC = src
	return n, err
}
