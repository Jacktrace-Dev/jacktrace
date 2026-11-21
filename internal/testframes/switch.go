package testframes

import (
	"encoding/binary"
	"net"
)

// SwitchMAC is the source MAC of the test switch port. It's a locally administered address
// (02:...), so it can't collide with real hardware.
var SwitchMAC = net.HardwareAddr{0x02, 0x4A, 0x54, 0x00, 0x00, 0x18}

// SwitchChassisMAC is the test switch's chassis MAC.
var SwitchChassisMAC = net.HardwareAddr{0x02, 0x4A, 0x54, 0x00, 0x00, 0x01}

// Org-specific OUIs.
var (
	OUI8021 = [3]byte{0x00, 0x80, 0xC2}
	OUI8023 = [3]byte{0x00, 0x12, 0x0F}
	OUIMED  = [3]byte{0x00, 0x12, 0xBB}
)

// AccessPortLLDP is what a Cisco C9200L access port with a desk phone profile sends over LLDP:
// the same port the README shows.
func AccessPortLLDP() []byte {
	voice := uint32(1)<<22 | 120<<9 | 5<<6 | 46 // tagged, VLAN 120, priority 5, DSCP 46
	return LLDPFrame(SwitchMAC,
		LLDPTLV(1, append([]byte{4}, SwitchChassisMAC...)),
		LLDPTLV(2, append([]byte{5}, "Gi1/0/24"...)),
		LLDPTLV(3, []byte{0, 120}),
		LLDPTLV(4, []byte("Room 114 desk")),
		LLDPTLV(5, []byte("IDF2-ACCESS-01")),
		LLDPTLV(6, []byte("Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4")),
		LLDPTLV(7, []byte{0x00, 0x14, 0x00, 0x04}), // system: bridge+router; enabled: bridge
		LLDPMgmtIPv4("10.0.20.2"),
		LLDPOrg(OUI8021, 1, []byte{0x00, 20}),                                           // PVID 20
		LLDPOrg(OUI8023, 1, []byte{0x03, 0x6C, 0x01, 0x00, 30}),                         // autoneg on, 1000BASE-T full
		LLDPOrg(OUI8023, 2, []byte{0x07, 0x01, 0x04, 0x12, 0x00, 154, 0x00, 154}),       // PSE, class 3, 15.4 W allocated
		LLDPOrg(OUIMED, 1, []byte{0x00, 0x33, 0x04}),                                    // MED capabilities
		LLDPOrg(OUIMED, 2, []byte{1, byte(voice >> 16), byte(voice >> 8), byte(voice)}), // voice policy
		LLDPOrg(OUIMED, 4, []byte{0x12, 0x00, 154}),                                     // PSE, primary, high: 15.4 W
	)
}

// AccessPortCDP is the same port's CDP announcement.
func AccessPortCDP() []byte {
	power := []byte{0x00, 0x01, 0x00, 0x01}
	power = binary.BigEndian.AppendUint32(power, 15400)
	power = binary.BigEndian.AppendUint32(power, 0xFFFFFFFF)
	return CDPFrame(SwitchMAC, 180,
		CDPTLV(0x0001, []byte("IDF2-ACCESS-01")),
		CDPAddresses(0x0002, "10.0.20.2"),
		CDPTLV(0x0003, []byte("GigabitEthernet1/0/24")),
		CDPTLV(0x0004, []byte{0x00, 0x00, 0x00, 0x28}), // switch, IGMP
		CDPTLV(0x0005, []byte("Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4")),
		CDPTLV(0x0006, []byte("cisco C9200L-48P-4G")),
		CDPTLV(0x0009, []byte("CAMPUS")),
		CDPTLV(0x000A, []byte{0x00, 20}),
		CDPTLV(0x000B, []byte{0x01}),
		CDPTLV(0x000E, []byte{0x01, 0x00, 120}),
		CDPTLV(0x001A, power),
		CDPAddresses(0x0016, "10.0.20.2"),
	)
}
