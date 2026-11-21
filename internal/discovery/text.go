package discovery

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// CleanText turns a text field from an announcement into something safe to print.
// Switch text is untrusted: a crafted System Name could carry terminal escape codes,
// so control characters are dropped, invalid UTF-8 is replaced, and NUL padding and
// surrounding space are trimmed.
func CleanText(b []byte) string {
	s := strings.ToValidUTF8(string(b), "�")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// FormatMAC renders a 6-byte MAC address as aa:bb:cc:dd:ee:ff.
// Anything that isn't 6 bytes is rendered as hex so nothing is silently lost.
func FormatMAC(b []byte) string {
	if len(b) == 6 {
		return net.HardwareAddr(b).String()
	}
	return fmt.Sprintf("%x", b)
}
