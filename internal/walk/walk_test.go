package walk

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/discovery"
	"github.com/jacktrace-dev/jacktrace/internal/report"
)

var at = time.Date(2026, 10, 25, 9, 30, 0, 0, time.UTC)

func port(sw, p string) report.Port {
	return report.Port{Adapter: "Ethernet (Intel(R) I219-V)", Switch: sw, Model: "Cisco C9200L-48P-4G",
		PortID: p, Description: "Room 114 desk", NativeVLAN: 20, VoiceVLAN: 120, ManagementIP: "10.0.20.2",
		PoEWatts: 15.4, Link: "1000BASE-T full", Via: []discovery.Protocol{discovery.CDP, discovery.LLDP}}
}

func TestNextLabel(t *testing.T) {
	cases := map[string]string{
		"R114-09":      "R114-10",
		"R114-99":      "R114-100",
		"2-114A":       "2-114B",
		"2-114a":       "2-114b",
		"2-114Z":       "",
		"D7":           "D8",
		"007":          "008",
		"1-14-B2":      "1-14-B3",
		"Lobby":        "",
		"":             "",
		"IDF2 #3 east": "IDF2 #4 east",
	}
	for in, want := range cases {
		if got := NextLabel(in); got != want {
			t.Errorf("NextLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSaveAndResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	a, err := Open(path)
	if err != nil || len(a.Rows) != 0 {
		t.Fatalf("new file: %v %v", a, err)
	}
	a.Put("R114-01", FromPort("R114-01", port("IDF2-ACCESS-01", "Gi1/0/24"), at))
	a.Put("R114-02", Nothing("R114-02", at))
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if !bytes.HasPrefix(raw, bom) || !bytes.Contains(raw, []byte("\r\n")) {
		t.Errorf("want a UTF-8 BOM and CRLF line endings for Excel")
	}
	want := "jack,status,switch,port,port_description,vlan,voice_vlan,mgmt_ip,poe_w,link,model,via,adapter,heard_at,note\r\n" +
		"R114-01,found,IDF2-ACCESS-01,Gi1/0/24,Room 114 desk,20,120,10.0.20.2,15.4,1000BASE-T full,Cisco C9200L-48P-4G,CDP + LLDP,Ethernet (Intel I219-V),2026-10-25 09:30:00,\r\n" +
		"R114-02,no switch heard,,,,,,,,,,,,2026-10-25 09:30:00,\r\n"
	if got := string(bytes.TrimPrefix(raw, bom)); got != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}

	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Rows) != 2 || b.Last() != "R114-02" || b.Jacks() != 2 || b.Rows[0] != a.Rows[0] {
		t.Errorf("resumed %+v", b.Rows)
	}
}

func TestRedoReplacesInPlace(t *testing.T) {
	a := &Audit{}
	a.Put("A1", Nothing("A1", at))
	a.Put("A2", Nothing("A2", at))
	a.Put("A3", Nothing("A3", at))
	a.Put("A2", FromPort("A2", port("SW", "Gi0/2"), at))
	var got []string
	for _, r := range a.Rows {
		got = append(got, r.Jack+":"+r.Status)
	}
	if strings.Join(got, " ") != "A1:no switch heard A2:found A3:no switch heard" {
		t.Errorf("got %v, want A2 replaced where it was", got)
	}
}

func TestDuplicate(t *testing.T) {
	a := &Audit{}
	a.Put("A1", FromPort("A1", port("IDF2-ACCESS-01", "Gi1/0/24"), at))
	a.Put("A2", Nothing("A2", at))
	if dup, ok := a.Duplicate(FromPort("A3", port("idf2-access-01", "GI1/0/24"), at)); !ok || dup != "A1" {
		t.Errorf("got %q %v, want A3 flagged as the same port as A1", dup, ok)
	}
	if _, ok := a.Duplicate(FromPort("A3", port("IDF2-ACCESS-01", "Gi1/0/25"), at)); ok {
		t.Error("a different port was flagged")
	}
	if _, ok := a.Duplicate(Nothing("A4", at)); ok {
		t.Error("a jack with no answer was flagged")
	}
	if _, ok := a.Duplicate(FromPort("A1", port("IDF2-ACCESS-01", "Gi1/0/24"), at)); ok {
		t.Error("redoing a jack flagged itself")
	}
}

func TestFormulaInjectionNeutralised(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.csv")
	a := &Audit{Path: path}
	evil := port(`=HYPERLINK("http://evil.example","click")`, "@SUM(1)")
	a.Put("+1", FromPort("+1", evil, at))
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, cell := range []string{`'=HYPERLINK`, `'@SUM(1)`, `'+1`} {
		if !bytes.Contains(raw, []byte(cell)) {
			t.Errorf("%s not neutralised:\n%s", cell, raw)
		}
	}
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if b.Rows[0].Switch != evil.Switch || b.Rows[0].Jack != "+1" {
		t.Errorf("reading back didn't restore the original text: %+v", b.Rows[0])
	}
}

func TestRefusesOtherCSVs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "budget.csv")
	os.WriteFile(path, []byte("date,amount\n2026-10-01,12.50\n"), 0o644)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "new file name") {
		t.Errorf("err = %v, want a refusal to overwrite an unrelated CSV", err)
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	a := &Audit{Path: filepath.Join(dir, "audit.csv")}
	a.Put("A1", Nothing("A1", at))
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("dir has %v, want only audit.csv", names)
	}
}
