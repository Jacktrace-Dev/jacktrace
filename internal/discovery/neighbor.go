// Package discovery holds the result type shared by the CDP and LLDP decoders.
package discovery

import (
	"errors"
	"time"
)

// Protocol is the discovery protocol a Neighbor was learned from.
type Protocol string

const (
	CDP  Protocol = "CDP"
	LLDP Protocol = "LLDP"
)

// ErrTruncated means the announcement was cut off before its end. The Neighbor returned with it
// holds whatever was decoded before the cut. A capture taken with a small snap length
// (pktmon's default is 128 bytes) produces this.
var ErrTruncated = errors.New("announcement is truncated")

// ValidVLAN reports whether v is a usable VLAN ID. 0 (priority tag only) and 4095 are reserved,
// and some devices send 4095 to mean "no VLAN".
func ValidVLAN(v int) bool { return v >= 1 && v <= 4094 }

// Neighbor is what one switch announcement tells us about the port on the other end of the cable.
// Fields the switch didn't send stay at their zero value.
type Neighbor struct {
	Protocol  Protocol  `json:"protocol"`
	Adapter   string    `json:"adapter,omitempty"`
	Received  time.Time `json:"received,omitzero"`
	SourceMAC string    `json:"source_mac,omitempty"`

	SwitchName        string   `json:"switch_name,omitempty"`
	ChassisID         string   `json:"chassis_id,omitempty"`
	Platform          string   `json:"platform,omitempty"`
	SoftwareVersion   string   `json:"software_version,omitempty"`
	SystemDescription string   `json:"system_description,omitempty"`
	ManagementIP      string   `json:"management_ip,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`

	PortID          string  `json:"port_id,omitempty"`
	PortDescription string  `json:"port_description,omitempty"`
	NativeVLAN      int     `json:"native_vlan,omitempty"`
	VoiceVLAN       int     `json:"voice_vlan,omitempty"`
	Duplex          string  `json:"duplex,omitempty"`
	Media           string  `json:"media,omitempty"`
	PoEWatts        float64 `json:"poe_watts,omitempty"`
	VTPDomain       string  `json:"vtp_domain,omitempty"`

	TTL time.Duration `json:"ttl,omitempty"`

	// Shutdown is set when the switch sends LLDP with a TTL of 0: "forget me, this port is
	// going away". Treat it as a withdrawal, not a result.
	Shutdown bool `json:"shutdown,omitempty"`

	// Truncated is set when the capture cut the announcement short, so later fields may be missing.
	Truncated bool `json:"truncated,omitempty"`
}
