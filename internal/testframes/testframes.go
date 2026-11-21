// Package testframes builds CDP and LLDP frames and capture files for tests.
// Everything here is generated from the specs, so the repo carries no third-party captures.
package testframes

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"
)

// ---- LLDP ----

// LLDPTLV encodes one LLDP TLV: 7-bit type, 9-bit length, value.
func LLDPTLV(typ int, value []byte) []byte {
	h := uint16(typ)<<9 | uint16(len(value))
	return append(binary.BigEndian.AppendUint16(nil, h), value...)
}

// LLDPOrg encodes an organizationally specific TLV (type 127).
func LLDPOrg(oui [3]byte, subtype byte, value []byte) []byte {
	return LLDPTLV(127, append([]byte{oui[0], oui[1], oui[2], subtype}, value...))
}

// LLDPMgmtIPv4 encodes a Management Address TLV for an IPv4 address with no interface or OID.
func LLDPMgmtIPv4(ip string) []byte {
	a := net.ParseIP(ip).To4()
	v := []byte{5, 1} // string length (subtype + 4 bytes), subtype IPv4
	v = append(v, a...)
	v = append(v, 1, 0, 0, 0, 0, 0) // interface numbering: unknown, number 0, OID length 0
	return LLDPTLV(8, v)
}

// LLDPMgmtIPv6 encodes a Management Address TLV for an IPv6 address.
func LLDPMgmtIPv6(ip string) []byte {
	a := net.ParseIP(ip).To16()
	v := []byte{17, 2}
	v = append(v, a...)
	v = append(v, 1, 0, 0, 0, 0, 0)
	return LLDPTLV(8, v)
}

// LLDPFrame wraps TLVs in an Ethernet frame to the LLDP multicast address and adds the End TLV.
func LLDPFrame(src net.HardwareAddr, tlvs ...[]byte) []byte {
	f := []byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}
	f = append(f, src...)
	f = append(f, 0x88, 0xCC)
	for _, t := range tlvs {
		f = append(f, t...)
	}
	f = append(f, LLDPTLV(0, nil)...)
	return pad(f)
}

// ---- CDP ----

// CDPTLV encodes one CDP TLV: type(2), length(2, includes these 4 bytes), value.
func CDPTLV(typ uint16, value []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(4+len(value)))
	return append(b, value...)
}

// CDPAddresses encodes an address list holding IPv4 addresses.
func CDPAddresses(typ uint16, ips ...string) []byte {
	v := binary.BigEndian.AppendUint32(nil, uint32(len(ips)))
	for _, ip := range ips {
		v = append(v, 1, 1, 0xCC, 0, 4) // NLPID, length 1, IP, address length 4
		v = append(v, net.ParseIP(ip).To4()...)
	}
	return CDPTLV(typ, v)
}

// CDPFrame wraps TLVs in an 802.3 + LLC/SNAP frame to the CDP multicast address,
// with a correct CDP checksum and minimum-size padding.
func CDPFrame(src net.HardwareAddr, ttl byte, tlvs ...[]byte) []byte {
	pdu := []byte{2, ttl, 0, 0}
	for _, t := range tlvs {
		pdu = append(pdu, t...)
	}
	binary.BigEndian.PutUint16(pdu[2:4], checksum(pdu))

	snap := []byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00}
	f := []byte{0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC}
	f = append(f, src...)
	f = binary.BigEndian.AppendUint16(f, uint16(len(snap)+len(pdu)))
	f = append(f, snap...)
	f = append(f, pdu...)
	return pad(f)
}

// checksum is the Internet checksum over the PDU, as CDP uses it.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

// pad brings a frame up to the 60-byte Ethernet minimum (without FCS).
func pad(f []byte) []byte {
	for len(f) < 60 {
		f = append(f, 0)
	}
	return f
}

// ---- capture files ----

// ByteOrder is what the capture writers need: reading and appending in one byte order.
// binary.LittleEndian and binary.BigEndian both satisfy it.
type ByteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

// Packet is one frame to write into a capture file.
type Packet struct {
	Time    time.Time
	Data    []byte
	OrigLen int    // 0 means len(Data)
	Comment string // pcapng only
}

// Pcapng writes a single-section, single-Ethernet-interface pcapng file in the given byte order,
// with nanosecond timestamps (if_tsresol = 9).
func Pcapng(order ByteOrder, pkts ...Packet) []byte {
	var out bytes.Buffer
	block := func(typ uint32, body []byte) {
		total := uint32(12 + len(body))
		b := order.AppendUint32(nil, typ)
		b = order.AppendUint32(b, total)
		b = append(b, body...)
		b = order.AppendUint32(b, total)
		out.Write(b)
	}
	option := func(b []byte, code uint16, val []byte) []byte {
		b = order.AppendUint16(b, code)
		b = order.AppendUint16(b, uint16(len(val)))
		b = append(b, val...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}

	shb := order.AppendUint32(nil, 0x1A2B3C4D)
	shb = order.AppendUint16(shb, 1)
	shb = order.AppendUint16(shb, 0)
	shb = order.AppendUint64(shb, 0xFFFFFFFFFFFFFFFF) // section length unknown
	block(0x0A0D0D0A, shb)

	idb := order.AppendUint16(nil, 1) // LINKTYPE_ETHERNET
	idb = order.AppendUint16(idb, 0)
	// Snap length 262144, as Wireshark writes it. The spec says 0 means "no limit", but
	// Apple's libpcap rejects every packet in a file that uses 0.
	idb = order.AppendUint32(idb, 262144)
	idb = option(idb, 9, []byte{9})  // if_tsresol: nanoseconds
	idb = order.AppendUint32(idb, 0) // opt_endofopt
	block(1, idb)

	for _, p := range pkts {
		orig := p.OrigLen
		if orig == 0 {
			orig = len(p.Data)
		}
		ns := uint64(p.Time.UnixNano())
		epb := order.AppendUint32(nil, 0)
		epb = order.AppendUint32(epb, uint32(ns>>32))
		epb = order.AppendUint32(epb, uint32(ns))
		epb = order.AppendUint32(epb, uint32(len(p.Data)))
		epb = order.AppendUint32(epb, uint32(orig))
		epb = append(epb, p.Data...)
		for len(epb)%4 != 0 {
			epb = append(epb, 0)
		}
		if p.Comment != "" {
			epb = option(epb, 1, []byte(p.Comment))
			epb = order.AppendUint32(epb, 0)
		}
		block(6, epb)
	}
	return out.Bytes()
}

// Pcap writes a classic libpcap file (Ethernet) in the given byte order,
// with microsecond or nanosecond timestamps.
func Pcap(order ByteOrder, nanos bool, pkts ...Packet) []byte {
	magic := uint32(0xA1B2C3D4)
	if nanos {
		magic = 0xA1B23C4D
	}
	b := order.AppendUint32(nil, magic)
	b = order.AppendUint16(b, 2)
	b = order.AppendUint16(b, 4)
	b = order.AppendUint32(b, 0)
	b = order.AppendUint32(b, 0)
	b = order.AppendUint32(b, 65535)
	b = order.AppendUint32(b, 1)
	for _, p := range pkts {
		orig := p.OrigLen
		if orig == 0 {
			orig = len(p.Data)
		}
		frac := p.Time.Nanosecond()
		if !nanos {
			frac /= 1000
		}
		b = order.AppendUint32(b, uint32(p.Time.Unix()))
		b = order.AppendUint32(b, uint32(frac))
		b = order.AppendUint32(b, uint32(len(p.Data)))
		b = order.AppendUint32(b, uint32(orig))
		b = append(b, p.Data...)
	}
	return b
}
