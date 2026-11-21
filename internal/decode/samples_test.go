package decode

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jacktrace-dev/jacktrace/internal/pcapfile"
)

// TestSamples decodes every capture in $JACKTRACE_SAMPLES and logs what it finds, for comparing
// against Wireshark or tcpdump by eye. Third-party captures stay out of the repo (see
// testdata/README.md), so this skips unless the variable points at a local folder:
//
//	JACKTRACE_SAMPLES=~/captures go test ./internal/decode -run TestSamples -v
func TestSamples(t *testing.T) {
	dir := os.Getenv("JACKTRACE_SAMPLES")
	if dir == "" {
		t.Skip("set JACKTRACE_SAMPLES to a folder of .pcap/.pcapng files")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		t.Run(f.Name(), func(t *testing.T) {
			fh, err := os.Open(filepath.Join(dir, f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			defer fh.Close()
			pkts, err := pcapfile.ReadAll(fh)
			if err != nil {
				t.Fatalf("reading: %v", err)
			}
			found := 0
			for i, p := range pkts {
				n, err := Frame(p.Data)
				if errors.Is(err, ErrNotDiscovery) {
					continue
				}
				found++
				js, _ := json.MarshalIndent(n, "", "  ")
				t.Logf("packet %d (err=%v):\n%s", i+1, err, js)
			}
			if found == 0 {
				t.Errorf("no CDP or LLDP frames in %d packets", len(pkts))
			}
		})
	}
}
