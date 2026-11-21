package pcapfile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	tf "github.com/jacktrace-dev/jacktrace/internal/testframes"
)

var at = time.Date(2026, 10, 21, 15, 4, 5, 123456789, time.UTC)

func TestPcapngBothByteOrders(t *testing.T) {
	for _, order := range []tf.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		file := tf.Pcapng(order,
			tf.Packet{Time: at, Data: tf.AccessPortLLDP(), Comment: "PktGroupId 1, Component 7"},
			tf.Packet{Time: at.Add(time.Second), Data: []byte{1, 2, 3}, OrigLen: 64},
		)
		pkts, err := ReadAll(bytes.NewReader(file))
		if err != nil {
			t.Fatalf("%v: %v", order, err)
		}
		if len(pkts) != 2 {
			t.Fatalf("%v: got %d packets", order, len(pkts))
		}
		p := pkts[0]
		if !p.Time.Equal(at) || p.LinkType != LinkTypeEthernet || !bytes.Equal(p.Data, tf.AccessPortLLDP()) {
			t.Errorf("%v: packet 0 = %+v", order, p)
		}
		if p.Comment != "PktGroupId 1, Component 7" {
			t.Errorf("%v: comment = %q", order, p.Comment)
		}
		if p.Truncated() || !pkts[1].Truncated() {
			t.Errorf("%v: truncation flags wrong", order)
		}
	}
}

func TestPcapClassic(t *testing.T) {
	for _, nanos := range []bool{false, true} {
		for _, order := range []tf.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			file := tf.Pcap(order, nanos, tf.Packet{Time: at, Data: tf.AccessPortCDP()})
			pkts, err := ReadAll(bytes.NewReader(file))
			if err != nil {
				t.Fatalf("nanos=%v %v: %v", nanos, order, err)
			}
			want := at
			if !nanos {
				want = at.Truncate(time.Microsecond)
			}
			if len(pkts) != 1 || !pkts[0].Time.Equal(want) || !bytes.Equal(pkts[0].Data, tf.AccessPortCDP()) {
				t.Errorf("nanos=%v %v: got %+v", nanos, order, pkts)
			}
		}
	}
}

func TestRejectsGarbage(t *testing.T) {
	for name, b := range map[string][]byte{
		"empty":      nil,
		"text":       []byte("hello world, not a capture"),
		"short pcap": {0xD4, 0xC3, 0xB2, 0xA1, 0x02},
	} {
		if _, err := ReadAll(bytes.NewReader(b)); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: err = %v, want ErrFormat", name, err)
		}
	}
}

func TestCorruptBlockTrailer(t *testing.T) {
	file := tf.Pcapng(binary.LittleEndian, tf.Packet{Time: at, Data: tf.AccessPortLLDP()})
	file[len(file)-1] ^= 0xFF
	if _, err := ReadAll(bytes.NewReader(file)); !errors.Is(err, ErrFormat) {
		t.Errorf("err = %v, want ErrFormat", err)
	}
}

func TestTimestampResolution(t *testing.T) {
	cases := []struct {
		v    byte
		unit time.Duration
		div  uint64
	}{
		{6, time.Microsecond, 0},
		{9, time.Nanosecond, 0},
		{3, time.Millisecond, 0},
		{12, 0, 1000},
		{0x80 | 10, time.Second / 1024, 0},
	}
	for _, c := range cases {
		unit, div := tsResolution(c.v)
		if unit != c.unit || div != c.div {
			t.Errorf("tsresol %#x = (%v, %d), want (%v, %d)", c.v, unit, div, c.unit, c.div)
		}
	}
}

func FuzzReader(f *testing.F) {
	f.Add(tf.Pcapng(binary.LittleEndian, tf.Packet{Time: at, Data: tf.AccessPortLLDP(), Comment: "x"}))
	f.Add(tf.Pcap(binary.BigEndian, true, tf.Packet{Time: at, Data: tf.AccessPortCDP()}))
	f.Fuzz(func(t *testing.T, b []byte) {
		ReadAll(bytes.NewReader(b)) // must never panic or hang
	})
}
