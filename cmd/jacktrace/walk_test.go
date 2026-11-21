package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/capture"
	"github.com/jacktrace-dev/jacktrace/internal/decode"
	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	"github.com/jacktrace-dev/jacktrace/internal/report"
	tf "github.com/jacktrace-dev/jacktrace/internal/testframes"
	"github.com/jacktrace-dev/jacktrace/internal/walk"
)

// c9200 decodes the C9200L test frames as if heard on the wired adapter.
func c9200(t *testing.T) []discovery.Neighbor {
	t.Helper()
	var out []discovery.Neighbor
	for _, f := range [][]byte{tf.AccessPortLLDP(), tf.AccessPortCDP()} {
		n, err := decode.Frame(f)
		if err != nil {
			t.Fatal(err)
		}
		n.Adapter = "Ethernet (Intel(R) Ethernet Connection I219-V)"
		out = append(out, n)
	}
	return out
}

func eeroNeighbor() []discovery.Neighbor {
	return []discovery.Neighbor{{Protocol: discovery.LLDP, Adapter: "Ethernet", SourceMAC: "02:00:5e:00:00:65",
		SwitchName: "eero", PortID: "2", PortDescription: "eth1"}}
}

type scripted struct {
	results [][]discovery.Neighbor
	errs    []error
	calls   int
}

func (s *scripted) capture(ctx context.Context, o capture.Options) ([]discovery.Neighbor, error) {
	i := s.calls
	s.calls++
	if o.OnListening != nil {
		o.OnListening([]capture.Adapter{{Name: "Ethernet", Up: true}})
	}
	var err error
	if i < len(s.errs) {
		err = s.errs[i]
	}
	if i < len(s.results) {
		return s.results[i], err
	}
	return nil, err
}

func newTestWalker(t *testing.T, path, input string, s *scripted) (*walker, *bytes.Buffer) {
	t.Helper()
	audit, err := walk.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	return &walker{
		in:      bufio.NewReader(strings.NewReader(input)),
		out:     &out,
		audit:   audit,
		opt:     capture.Options{Timeout: time.Minute, Done: capture.Settled},
		capture: s.capture,
		newLive: func() *report.Live { return report.NewLive(&out, false, false, "test", time.Minute) },
		now:     func() time.Time { return time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC) },
		notify:  func(ctx context.Context) (context.Context, context.CancelFunc) { return context.WithCancel(ctx) },
	}, &out
}

func TestWalkThreeJacks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	s := &scripted{results: [][]discovery.Neighbor{c9200(t), eeroNeighbor(), c9200(t)}}
	// R114-01 typed, Enter accepts R114-02, R114-03 typed, then done.
	w, out := newTestWalker(t, path, "R114-01\n\nR114-03\nq\n", s)
	if code := w.run(); code != exitFound {
		t.Fatalf("exit %d\n%s", code, out)
	}
	a, err := walk.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range a.Rows {
		got = append(got, r.Jack+"="+r.Switch+" "+r.Port+" "+r.Note)
	}
	want := []string{
		"R114-01=IDF2-ACCESS-01 Gi1/0/24 ",
		"R114-02=eero 2 ",
		"R114-03=IDF2-ACCESS-01 Gi1/0/24 same port as R114-01",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	text := out.String()
	for _, s := range []string{
		"[Enter = R114-02, r = redo R114-01, q = done]",
		"✓ R114-01 → IDF2-ACCESS-01 Gi1/0/24 · VLAN 20, voice 120",
		"⚠ Same port as R114-01. Did the cable move?",
		"3 jacks in " + path + ": 3 found, 0 with no answer, 1 on a port already recorded",
	} {
		if !strings.Contains(text, s) {
			t.Errorf("output missing %q:\n%s", s, text)
		}
	}
}

func TestWalkRedoAndResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	s := &scripted{results: [][]discovery.Neighbor{nil, c9200(t)}}
	w, out := newTestWalker(t, path, "D7\nr\nq\n", s)
	w.run()
	if !strings.Contains(out.String(), "✗ D7: no switch heard") || !strings.Contains(out.String(), "D7 is already recorded; this replaces it.") {
		t.Errorf("output:\n%s", out)
	}

	// Come back later: the next suggestion continues from D7.
	s2 := &scripted{results: [][]discovery.Neighbor{eeroNeighbor()}}
	w2, out2 := newTestWalker(t, path, "\nq\n", s2)
	w2.run()
	if !strings.Contains(out2.String(), "Carrying on: 1 jack already recorded, last was D7.") {
		t.Errorf("resume output:\n%s", out2)
	}
	a, _ := walk.Open(path)
	if len(a.Rows) != 2 || a.Rows[0].Jack != "D7" || a.Rows[0].Status != walk.StatusFound || a.Rows[1].Jack != "D8" {
		t.Errorf("rows %+v", a.Rows)
	}
}

func TestWalkCtrlCKeepsEarlierJacks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	s := &scripted{results: [][]discovery.Neighbor{eeroNeighbor(), nil}, errs: []error{nil, context.Canceled}}
	w, out := newTestWalker(t, path, "A1\nA2\n", s)
	if code := w.run(); code != exitInterrupted {
		t.Fatalf("exit %d, want %d", code, exitInterrupted)
	}
	if !strings.Contains(out.String(), "Stopped. A2 wasn't recorded") {
		t.Errorf("output:\n%s", out)
	}
	a, _ := walk.Open(path)
	if len(a.Rows) != 1 || a.Rows[0].Jack != "A1" {
		t.Errorf("rows %+v, want only A1", a.Rows)
	}
}

func TestWalkEndOfInputFinishes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	w, out := newTestWalker(t, path, "Lobby", &scripted{results: [][]discovery.Neighbor{eeroNeighbor()}})
	if code := w.run(); code != exitFound {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// "Lobby" has no number, so there's no suggestion; Enter alone asks for a label.
	if a, _ := walk.Open(path); len(a.Rows) != 1 {
		t.Errorf("rows %+v", a.Rows)
	}
}

func TestWalkEmptyEnterWithoutSuggestion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	w, out := newTestWalker(t, path, "\nq\n", &scripted{})
	w.run()
	if !strings.Contains(out.String(), "Type a label for this jack") {
		t.Errorf("output:\n%s", out)
	}
}

func TestWalkFileLocked(t *testing.T) {
	// A directory where the CSV should be makes every save fail, like Excel holding the file.
	dir := t.TempDir()
	locked := filepath.Join(dir, "audit.csv")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	s := &scripted{results: [][]discovery.Neighbor{eeroNeighbor()}}
	w, out := newTestWalker(t, filepath.Join(dir, "unused.csv"), "A1\nq\nq\n", s)
	w.audit.Path = locked
	if code := w.run(); code != exitError {
		t.Fatalf("exit %d, want %d", code, exitError)
	}
	for _, s := range []string{"If it's open in Excel, close it. Nothing is lost", "Close it in Excel and press Enter to try again"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("output missing %q:\n%s", s, out)
		}
	}
}

func TestWalkSummaryCountsWholeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	w, _ := newTestWalker(t, path, "J-01\n\nq\n", &scripted{results: [][]discovery.Neighbor{eeroNeighbor(), eeroNeighbor()}})
	w.run()
	// Resume and add a third jack on the same port: the summary must count both warnings.
	w2, out := newTestWalker(t, path, "\nq\n", &scripted{results: [][]discovery.Neighbor{eeroNeighbor()}})
	w2.run()
	if !strings.Contains(out.String(), "3 found, 0 with no answer, 2 on a port already recorded") {
		t.Errorf("summary:\n%s", out)
	}
}
