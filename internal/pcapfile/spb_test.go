package pcapfile

import (
	"encoding/binary"
	"errors"
	"testing"
)

// spb builds a simple packet block body: the original length (little-endian), then data.
func spb(origLen uint32, data string) []byte {
	return append(binary.LittleEndian.AppendUint32(nil, origLen), data...)
}

func TestParseSPB(t *testing.T) {
	eth := func(snap int) *Reader {
		return &Reader{order: binary.LittleEndian, ifaces: []iface{{linkType: LinkTypeEthernet, snapLen: snap}}}
	}
	cases := []struct {
		name     string
		rd       *Reader
		body     []byte
		wantErr  bool
		wantOrig int
		wantData string
	}{
		{name: "body shorter than 4 bytes", rd: eth(0), body: []byte{1, 2}, wantErr: true},
		{name: "no interfaces", rd: &Reader{order: binary.LittleEndian}, body: spb(4, "abcd"), wantErr: true},
		{name: "original longer than data present", rd: eth(0), body: spb(16, "12345"), wantOrig: 16, wantData: "12345"},
		{name: "snapLen smaller than data", rd: eth(3), body: spb(100, "1234567890"), wantOrig: 100, wantData: "123"},
	}
	for _, tc := range cases {
		pkt, err := tc.rd.parseSPB(tc.body)
		if tc.wantErr {
			if !errors.Is(err, ErrFormat) {
				t.Errorf("%s: err = %v, want ErrFormat", tc.name, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if string(pkt.Data) != tc.wantData || pkt.OrigLen != tc.wantOrig || pkt.LinkType != LinkTypeEthernet {
			t.Errorf("%s: got data %q, orig %d, link %v; want %q, %d, Ethernet", tc.name, pkt.Data, pkt.OrigLen, pkt.LinkType, tc.wantData, tc.wantOrig)
		}
	}
}
