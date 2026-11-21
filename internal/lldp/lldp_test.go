package lldp

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	tf "github.com/jacktrace-dev/jacktrace/internal/testframes"
)

// pdu strips the 14-byte Ethernet header from a test frame.
func pdu(frame []byte) []byte { return frame[14:] }

func TestAccessPort(t *testing.T) {
	got, err := Parse(pdu(tf.AccessPortLLDP()))
	if err != nil {
		t.Fatal(err)
	}
	want := discovery.Neighbor{
		Protocol:          discovery.LLDP,
		SwitchName:        "IDF2-ACCESS-01",
		ChassisID:         "02:4a:54:00:00:01",
		SystemDescription: "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4",
		ManagementIP:      "10.0.20.2",
		Capabilities:      []string{"Bridge"},
		PortID:            "Gi1/0/24",
		PortDescription:   "Room 114 desk",
		NativeVLAN:        20,
		VoiceVLAN:         120,
		Duplex:            "full",
		Media:             "1000BASE-T",
		PoEWatts:          15.4,
		TTL:               120 * time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestMinimal(t *testing.T) {
	got, err := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC,
		tf.LLDPTLV(1, []byte{7, 'c', 'h'}),
		tf.LLDPTLV(2, []byte{3, 0x02, 0, 0, 0, 0, 0x05}),
		tf.LLDPTLV(3, []byte{0, 30}),
	)))
	if err != nil {
		t.Fatal(err)
	}
	if got.ChassisID != "ch" || got.PortID != "02:00:00:00:00:05" || got.TTL != 30*time.Second {
		t.Errorf("got %+v", got)
	}
}

func TestChassisNetworkAddress(t *testing.T) {
	got, err := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC,
		tf.LLDPTLV(1, []byte{5, 1, 192, 0, 2, 7}),
		tf.LLDPTLV(2, []byte{5, 'p', '1'}),
		tf.LLDPTLV(3, []byte{0, 30}),
	)))
	if err != nil {
		t.Fatal(err)
	}
	if got.ChassisID != "192.0.2.7" {
		t.Errorf("chassis = %q", got.ChassisID)
	}
}

func TestPrefersIPv4Management(t *testing.T) {
	got, _ := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC,
		tf.LLDPTLV(1, []byte{7, 'c'}),
		tf.LLDPTLV(2, []byte{7, 'p'}),
		tf.LLDPTLV(3, []byte{0, 30}),
		tf.LLDPMgmtIPv6("2001:db8::2"),
		tf.LLDPMgmtIPv4("192.0.2.2"),
		tf.LLDPMgmtIPv4("192.0.2.99"),
	)))
	if got.ManagementIP != "192.0.2.2" {
		t.Errorf("management IP = %q, want the first IPv4", got.ManagementIP)
	}
}

func TestVoicePolicyUnknownIsIgnored(t *testing.T) {
	unknown := uint32(1)<<23 | 120<<9
	got, _ := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC,
		tf.LLDPTLV(1, []byte{7, 'c'}),
		tf.LLDPTLV(2, []byte{7, 'p'}),
		tf.LLDPTLV(3, []byte{0, 30}),
		tf.LLDPOrg(tf.OUIMED, 2, []byte{1, byte(unknown >> 16), byte(unknown >> 8), byte(unknown)}),
	)))
	if got.VoiceVLAN != 0 {
		t.Errorf("voice VLAN = %d, want 0 for an 'unknown' policy", got.VoiceVLAN)
	}
}

func TestTruncatedReturnsPartial(t *testing.T) {
	full := pdu(tf.AccessPortLLDP())
	// pktmon's default 128-byte snap length leaves 114 bytes after the Ethernet header.
	got, err := Parse(full[:114])
	if !errors.Is(err, discovery.ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
	if got.ChassisID == "" || got.PortID != "Gi1/0/24" || got.SwitchName != "IDF2-ACCESS-01" {
		t.Errorf("partial result lost early fields: %+v", got)
	}
}

func TestMissingMandatory(t *testing.T) {
	_, err := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC, tf.LLDPTLV(5, []byte("only-a-name")))))
	if err == nil || errors.Is(err, discovery.ErrTruncated) {
		t.Errorf("err = %v, want a malformed (not truncated) error", err)
	}
}

func TestEscapeCodesStripped(t *testing.T) {
	got, _ := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC,
		tf.LLDPTLV(1, []byte{7, 'c'}),
		tf.LLDPTLV(2, []byte{7, 'p'}),
		tf.LLDPTLV(3, []byte{0, 30}),
		tf.LLDPTLV(5, []byte("evil\x1b[2J\x1b]0;pwned\x07switch")),
	)))
	if got.SwitchName != "evil[2J]0;pwnedswitch" {
		t.Errorf("switch name = %q", got.SwitchName)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(pdu(tf.AccessPortLLDP()))
	f.Add([]byte{0x02, 0x07, 0x04})
	f.Add([]byte{0xFE, 0x04, 0x00, 0x12, 0xBB, 0x02})
	f.Fuzz(func(t *testing.T, b []byte) {
		Parse(b) // must never panic
	})
}

func TestShutdown(t *testing.T) {
	got, err := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC,
		tf.LLDPTLV(1, []byte{7, 'c'}),
		tf.LLDPTLV(2, []byte{7, 'p'}),
		tf.LLDPTLV(3, []byte{0, 0}),
	)))
	if err != nil || !got.Shutdown {
		t.Errorf("got %+v, %v; want Shutdown", got, err)
	}
}

func TestReservedVLANsIgnored(t *testing.T) {
	for _, vlan := range []uint32{0, 4095} {
		policy := uint32(1)<<22 | vlan<<9
		got, _ := Parse(pdu(tf.LLDPFrame(tf.SwitchMAC,
			tf.LLDPTLV(1, []byte{7, 'c'}),
			tf.LLDPTLV(2, []byte{7, 'p'}),
			tf.LLDPTLV(3, []byte{0, 30}),
			tf.LLDPOrg(tf.OUI8021, 1, []byte{byte(vlan >> 8), byte(vlan)}),
			tf.LLDPOrg(tf.OUIMED, 2, []byte{1, byte(policy >> 16), byte(policy >> 8), byte(policy)}),
		)))
		if got.NativeVLAN != 0 || got.VoiceVLAN != 0 {
			t.Errorf("VLAN %d: got native %d voice %d, want both 0", vlan, got.NativeVLAN, got.VoiceVLAN)
		}
	}
}
