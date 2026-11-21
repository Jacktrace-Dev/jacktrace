// Package pcapfile reads packet capture files in the pcapng format (what pktmon writes) and the
// older libpcap format (what most tools and public sample captures use).
//
// It reads only what JackTrace needs: link type, timestamp, packet bytes and the per-packet
// comment. Malformed input returns an error; it never panics and never allocates more than
// MaxBlockSize for a single block.
package pcapfile

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// LinkTypeEthernet is the only link type JackTrace decodes.
const LinkTypeEthernet = 1

// MaxBlockSize caps a single pcapng block or pcap record so a corrupt length field can't
// make us allocate gigabytes.
const MaxBlockSize = 16 << 20

// ErrFormat is returned (wrapped) for anything that isn't a valid capture file.
var ErrFormat = errors.New("not a valid capture file")

// Packet is one captured frame.
type Packet struct {
	Time      time.Time
	LinkType  int
	Interface int    // pcapng interface index; always 0 for libpcap files
	OrigLen   int    // length on the wire, which may exceed len(Data) if the capture truncated it
	Data      []byte // the captured bytes
	Comment   string // pcapng opt_comment, if any (pktmon puts component details here)
}

// Truncated reports whether the capture kept fewer bytes than were on the wire.
func (p Packet) Truncated() bool { return len(p.Data) < p.OrigLen }

// Reader returns packets one at a time.
type Reader struct {
	r    *bufio.Reader
	next func() (Packet, error)

	// libpcap state
	order    binary.ByteOrder
	nanos    bool
	linkType int

	// pcapng state
	ifaces []iface
}

type iface struct {
	linkType int
	snapLen  int
	tsUnit   time.Duration // duration of one timestamp tick; 0 means sub-nanosecond
	tsDiv    uint64        // ticks per nanosecond when tsUnit is 0
}

// NewReader detects the file format from its first bytes.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	rd := &Reader{r: br}
	switch {
	case binary.LittleEndian.Uint32(magic) == 0x0A0D0D0A:
		rd.next = rd.nextPcapng
	case isPcapMagic(magic):
		if err := rd.readPcapHeader(); err != nil {
			return nil, err
		}
		rd.next = rd.nextPcap
	default:
		return nil, fmt.Errorf("%w: unknown magic %x", ErrFormat, magic)
	}
	return rd, nil
}

// Next returns the next packet, or io.EOF when the file ends cleanly.
func (rd *Reader) Next() (Packet, error) { return rd.next() }

// ReadAll is a convenience for small files and tests.
func ReadAll(r io.Reader) ([]Packet, error) {
	rd, err := NewReader(r)
	if err != nil {
		return nil, err
	}
	var out []Packet
	for {
		p, err := rd.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
}

// ---- libpcap ----

func isPcapMagic(m []byte) bool {
	switch binary.LittleEndian.Uint32(m) {
	case 0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1:
		return true
	}
	return false
}

func (rd *Reader) readPcapHeader() error {
	h := make([]byte, 24)
	if _, err := io.ReadFull(rd.r, h); err != nil {
		return fmt.Errorf("%w: short pcap header", ErrFormat)
	}
	switch binary.LittleEndian.Uint32(h) {
	case 0xA1B2C3D4:
		rd.order = binary.LittleEndian
	case 0xA1B23C4D:
		rd.order, rd.nanos = binary.LittleEndian, true
	case 0xD4C3B2A1:
		rd.order = binary.BigEndian
	case 0x4D3CB2A1:
		rd.order, rd.nanos = binary.BigEndian, true
	}
	// The link type sits in the low 16 bits; the upper bits can carry FCS flags.
	rd.linkType = int(rd.order.Uint32(h[20:24]) & 0xFFFF)
	return nil
}

func (rd *Reader) nextPcap() (Packet, error) {
	h := make([]byte, 16)
	if _, err := io.ReadFull(rd.r, h); err != nil {
		if err == io.EOF {
			return Packet{}, io.EOF
		}
		return Packet{}, fmt.Errorf("%w: short record header", ErrFormat)
	}
	sec := int64(rd.order.Uint32(h[0:4]))
	frac := int64(rd.order.Uint32(h[4:8]))
	inclLen := rd.order.Uint32(h[8:12])
	origLen := rd.order.Uint32(h[12:16])
	if inclLen > MaxBlockSize {
		return Packet{}, fmt.Errorf("%w: record of %d bytes", ErrFormat, inclLen)
	}
	data := make([]byte, inclLen)
	if _, err := io.ReadFull(rd.r, data); err != nil {
		return Packet{}, fmt.Errorf("%w: record cut short", ErrFormat)
	}
	if !rd.nanos {
		frac *= 1000
	}
	return Packet{
		Time:     time.Unix(sec, frac).UTC(),
		LinkType: rd.linkType,
		OrigLen:  int(origLen),
		Data:     data,
	}, nil
}

// ---- pcapng ----

const (
	blockSHB = 0x0A0D0D0A
	blockIDB = 0x00000001
	blockPB  = 0x00000002 // obsolete Packet Block
	blockSPB = 0x00000003
	blockEPB = 0x00000006
)

func (rd *Reader) nextPcapng() (Packet, error) {
	for {
		typ, body, err := rd.readBlock()
		if err != nil {
			return Packet{}, err
		}
		switch typ {
		case blockSHB:
			rd.ifaces = rd.ifaces[:0] // a new section starts a new interface list
		case blockIDB:
			if err := rd.addInterface(body); err != nil {
				return Packet{}, err
			}
		case blockEPB:
			return rd.parseEPB(body)
		case blockSPB:
			return rd.parseSPB(body)
		case blockPB:
			return rd.parsePB(body)
		}
		// Every other block type (name resolution, statistics, custom...) is skipped.
	}
}

// readBlock reads one block and returns its type and body (without the type and length fields).
// The Section Header Block also sets the byte order for everything after it.
func (rd *Reader) readBlock() (uint32, []byte, error) {
	h, err := rd.r.Peek(8)
	if err != nil {
		if err == io.EOF && len(h) == 0 {
			return 0, nil, io.EOF
		}
		return 0, nil, fmt.Errorf("%w: short block header", ErrFormat)
	}
	if binary.LittleEndian.Uint32(h[0:4]) == blockSHB {
		bom, err := rd.r.Peek(12)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: short section header", ErrFormat)
		}
		switch {
		case binary.LittleEndian.Uint32(bom[8:12]) == 0x1A2B3C4D:
			rd.order = binary.LittleEndian
		case binary.BigEndian.Uint32(bom[8:12]) == 0x1A2B3C4D:
			rd.order = binary.BigEndian
		default:
			return 0, nil, fmt.Errorf("%w: bad byte-order magic", ErrFormat)
		}
	}
	if rd.order == nil {
		return 0, nil, fmt.Errorf("%w: block before section header", ErrFormat)
	}
	typ := rd.order.Uint32(h[0:4])
	total := rd.order.Uint32(h[4:8])
	if total < 12 || total%4 != 0 || total > MaxBlockSize {
		return 0, nil, fmt.Errorf("%w: block length %d", ErrFormat, total)
	}
	buf := make([]byte, total)
	if _, err := io.ReadFull(rd.r, buf); err != nil {
		return 0, nil, fmt.Errorf("%w: block cut short", ErrFormat)
	}
	if rd.order.Uint32(buf[total-4:]) != total {
		return 0, nil, fmt.Errorf("%w: block trailer mismatch", ErrFormat)
	}
	return typ, buf[8 : total-4], nil
}

func (rd *Reader) addInterface(body []byte) error {
	if len(body) < 8 {
		return fmt.Errorf("%w: short interface block", ErrFormat)
	}
	ifc := iface{
		linkType: int(rd.order.Uint16(body[0:2])),
		snapLen:  int(rd.order.Uint32(body[4:8])),
		tsUnit:   time.Microsecond,
	}
	for code, val := range rd.options(body[8:]) {
		if code == 9 && len(val) >= 1 { // if_tsresol
			ifc.tsUnit, ifc.tsDiv = tsResolution(val[0])
		}
	}
	rd.ifaces = append(rd.ifaces, ifc)
	return nil
}

// tsResolution decodes if_tsresol: the high bit picks base 2 instead of base 10.
func tsResolution(v byte) (time.Duration, uint64) {
	exp := uint(v & 0x7F)
	if v&0x80 != 0 {
		if exp > 62 {
			exp = 62
		}
		ticksPerSec := uint64(1) << exp
		if ticksPerSec <= 1e9 {
			return time.Duration(1e9 / ticksPerSec), 0
		}
		return 0, ticksPerSec / 1e9
	}
	if exp <= 9 {
		d := time.Second
		for i := uint(0); i < exp; i++ {
			d /= 10
		}
		return d, 0
	}
	div := uint64(1)
	for i := uint(9); i < exp && i < 19; i++ {
		div *= 10
	}
	return 0, div
}

func (rd *Reader) iface(id int) (iface, error) {
	if id < 0 || id >= len(rd.ifaces) {
		return iface{}, fmt.Errorf("%w: packet for unknown interface %d", ErrFormat, id)
	}
	return rd.ifaces[id], nil
}

func (ifc iface) time(ticks uint64) time.Time {
	if ifc.tsUnit > 0 {
		sec := uint64(time.Second / ifc.tsUnit)
		return time.Unix(int64(ticks/sec), int64(ticks%sec)*int64(ifc.tsUnit)).UTC()
	}
	ns := ticks / ifc.tsDiv
	return time.Unix(0, int64(ns)).UTC()
}

func (rd *Reader) parseEPB(body []byte) (Packet, error) {
	if len(body) < 20 {
		return Packet{}, fmt.Errorf("%w: short enhanced packet block", ErrFormat)
	}
	id := int(rd.order.Uint32(body[0:4]))
	ifc, err := rd.iface(id)
	if err != nil {
		return Packet{}, err
	}
	ticks := uint64(rd.order.Uint32(body[4:8]))<<32 | uint64(rd.order.Uint32(body[8:12]))
	capLen := int(rd.order.Uint32(body[12:16]))
	origLen := int(rd.order.Uint32(body[16:20]))
	padded := (capLen + 3) &^ 3
	if capLen < 0 || 20+padded > len(body) {
		return Packet{}, fmt.Errorf("%w: packet data overruns block", ErrFormat)
	}
	p := Packet{
		Time:      ifc.time(ticks),
		LinkType:  ifc.linkType,
		Interface: id,
		OrigLen:   origLen,
		Data:      body[20 : 20+capLen],
	}
	if c, ok := rd.options(body[20+padded:])[1]; ok { // opt_comment
		p.Comment = string(c)
	}
	return p, nil
}

func (rd *Reader) parseSPB(body []byte) (Packet, error) {
	if len(body) < 4 {
		return Packet{}, fmt.Errorf("%w: short simple packet block", ErrFormat)
	}
	ifc, err := rd.iface(0)
	if err != nil {
		return Packet{}, err
	}
	origLen := int(rd.order.Uint32(body[0:4]))
	capLen := min(origLen, len(body)-4)
	if ifc.snapLen > 0 {
		capLen = min(capLen, ifc.snapLen)
	}
	return Packet{LinkType: ifc.linkType, OrigLen: origLen, Data: body[4 : 4+capLen]}, nil
}

func (rd *Reader) parsePB(body []byte) (Packet, error) {
	if len(body) < 20 {
		return Packet{}, fmt.Errorf("%w: short packet block", ErrFormat)
	}
	id := int(rd.order.Uint16(body[0:2]))
	ifc, err := rd.iface(id)
	if err != nil {
		return Packet{}, err
	}
	ticks := uint64(rd.order.Uint32(body[4:8]))<<32 | uint64(rd.order.Uint32(body[8:12]))
	capLen := int(rd.order.Uint32(body[12:16]))
	origLen := int(rd.order.Uint32(body[16:20]))
	if capLen < 0 || 20+capLen > len(body) {
		return Packet{}, fmt.Errorf("%w: packet data overruns block", ErrFormat)
	}
	return Packet{
		Time:      ifc.time(ticks),
		LinkType:  ifc.linkType,
		Interface: id,
		OrigLen:   origLen,
		Data:      body[20 : 20+capLen],
	}, nil
}

// options walks a pcapng option list. Later duplicates of a code overwrite earlier ones,
// which is fine for the options we read. A malformed list stops quietly: options are
// optional, so a bad one shouldn't cost us the packet.
func (rd *Reader) options(b []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(b) >= 4 {
		code := rd.order.Uint16(b[0:2])
		n := int(rd.order.Uint16(b[2:4]))
		if code == 0 { // opt_endofopt
			break
		}
		padded := (n + 3) &^ 3
		if 4+padded > len(b) {
			break
		}
		out[code] = b[4 : 4+n]
		b = b[4+padded:]
	}
	return out
}
