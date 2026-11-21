package decode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	"github.com/jacktrace-dev/jacktrace/internal/pcapfile"
	tf "github.com/jacktrace-dev/jacktrace/internal/testframes"
)

var update = flag.Bool("update", false, "rewrite the generated capture files in testdata/")

func TestLLDPFrame(t *testing.T) {
	n, err := Frame(tf.AccessPortLLDP())
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != discovery.LLDP || n.PortID != "Gi1/0/24" || n.SourceMAC != "02:4a:54:00:00:18" {
		t.Errorf("got %+v", n)
	}
}

func TestCDPFrame(t *testing.T) {
	n, err := Frame(tf.AccessPortCDP())
	if err != nil {
		t.Fatal(err)
	}
	if n.Protocol != discovery.CDP || n.PortID != "GigabitEthernet1/0/24" || n.SourceMAC != "02:4a:54:00:00:18" {
		t.Errorf("got %+v", n)
	}
}

func TestVLANTaggedLLDP(t *testing.T) {
	f := tf.AccessPortLLDP()
	tagged := append(append(append([]byte{}, f[:12]...), 0x81, 0x00, 0x00, 0x14), f[12:]...)
	n, err := Frame(tagged)
	if err != nil {
		t.Fatal(err)
	}
	if n.PortID != "Gi1/0/24" {
		t.Errorf("got %+v", n)
	}
}

func TestNotDiscovery(t *testing.T) {
	cases := map[string][]byte{
		"empty":     nil,
		"short":     make([]byte, 13),
		"ipv4":      append(make([]byte, 12), 0x08, 0x00, 0x45),
		"802.3 STP": append(make([]byte, 12), 0x00, 0x26, 0x42, 0x42, 0x03),
		"tiny len":  append(make([]byte, 12), 0x00, 0x04, 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00),
	}
	for name, f := range cases {
		if _, err := Frame(f); !errors.Is(err, ErrNotDiscovery) {
			t.Errorf("%s: err = %v, want ErrNotDiscovery", name, err)
		}
	}
}

// TestCaptureFile decodes the generated pcapng in testdata/: the same path pktmon output will take.
// Run with -update to regenerate it.
func TestCaptureFile(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "c9200-access-port.pcapng")
	if *update {
		at := time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC)
		data := tf.Pcapng(binary.LittleEndian,
			tf.Packet{Time: at, Data: tf.AccessPortLLDP()},
			tf.Packet{Time: at.Add(12 * time.Second), Data: append(make([]byte, 12), 0x08, 0x00, 0x45, 0x00)},
			tf.Packet{Time: at.Add(31 * time.Second), Data: tf.AccessPortCDP()},
		)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pkts, err := pcapfile.ReadAll(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var got []discovery.Protocol
	for _, p := range pkts {
		n, err := Frame(p.Data)
		if errors.Is(err, ErrNotDiscovery) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, n.Protocol)
	}
	if len(got) != 2 || got[0] != discovery.LLDP || got[1] != discovery.CDP {
		t.Errorf("decoded %v, want [LLDP CDP]", got)
	}
}

func FuzzFrame(f *testing.F) {
	f.Add(tf.AccessPortLLDP())
	f.Add(tf.AccessPortCDP())
	f.Fuzz(func(t *testing.T, b []byte) {
		Frame(b) // must never panic
	})
}
