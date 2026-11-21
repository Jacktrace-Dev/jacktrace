package cdp

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	tf "github.com/jacktrace-dev/jacktrace/internal/testframes"
)

// pdu strips the Ethernet header (14 bytes) and LLC/SNAP header (8 bytes) from a test frame,
// trimming the padding using the 802.3 length field.
func pdu(frame []byte) []byte {
	n := int(frame[12])<<8 | int(frame[13])
	return frame[22 : 14+n]
}

func TestAccessPort(t *testing.T) {
	got, err := Parse(pdu(tf.AccessPortCDP()))
	if err != nil {
		t.Fatal(err)
	}
	want := discovery.Neighbor{
		Protocol:        discovery.CDP,
		SwitchName:      "IDF2-ACCESS-01",
		Platform:        "cisco C9200L-48P-4G",
		SoftwareVersion: "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4",
		ManagementIP:    "10.0.20.2",
		Capabilities:    []string{"Switch", "IGMP"},
		PortID:          "GigabitEthernet1/0/24",
		NativeVLAN:      20,
		VoiceVLAN:       120,
		Duplex:          "full",
		PoEWatts:        15.4,
		VTPDomain:       "CAMPUS",
		TTL:             180 * time.Second,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestFallsBackToInterfaceAddress(t *testing.T) {
	got, err := Parse(pdu(tf.CDPFrame(tf.SwitchMAC, 180,
		tf.CDPTLV(0x0001, []byte("sw")),
		tf.CDPAddresses(0x0002, "192.0.2.10"),
	)))
	if err != nil {
		t.Fatal(err)
	}
	if got.ManagementIP != "192.0.2.10" {
		t.Errorf("management IP = %q", got.ManagementIP)
	}
}

func TestTruncatedReturnsPartial(t *testing.T) {
	full := pdu(tf.AccessPortCDP())
	got, err := Parse(full[:70]) // cuts into the Capabilities TLV, after Port ID
	if !errors.Is(err, discovery.ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
	if got.SwitchName != "IDF2-ACCESS-01" || got.PortID != "GigabitEthernet1/0/24" {
		t.Errorf("partial result lost early fields: %+v", got)
	}
}

func TestBadVersion(t *testing.T) {
	if _, err := Parse([]byte{9, 180, 0, 0}); err == nil {
		t.Error("want an error for CDP version 9")
	}
}

func TestImpossibleTLVLength(t *testing.T) {
	_, err := Parse([]byte{2, 180, 0, 0, 0x00, 0x01, 0x00, 0x02})
	if err == nil || errors.Is(err, discovery.ErrTruncated) {
		t.Errorf("err = %v, want a malformed (not truncated) error", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(pdu(tf.AccessPortCDP()))
	f.Add([]byte{2, 180, 0, 0, 0x00, 0x02, 0x00, 0x08, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, b []byte) {
		Parse(b) // must never panic
	})
}

func TestReservedVoiceVLANIgnored(t *testing.T) {
	// A Broadcom BCM1100 phone design sends VoIP VLAN 4095 (Wireshark's cdp-BCM1100 sample).
	got, err := Parse(pdu(tf.CDPFrame(tf.SwitchMAC, 180,
		tf.CDPTLV(0x0001, []byte("phone")),
		tf.CDPTLV(0x000E, []byte{0x01, 0x0F, 0xFF}),
		tf.CDPTLV(0x000A, []byte{0x0F, 0xFF}),
	)))
	if err != nil {
		t.Fatal(err)
	}
	if got.VoiceVLAN != 0 || got.NativeVLAN != 0 {
		t.Errorf("got voice %d native %d, want both 0", got.VoiceVLAN, got.NativeVLAN)
	}
}
