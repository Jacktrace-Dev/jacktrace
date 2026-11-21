// Package walk keeps the audit file for walk mode: one CSV row per jack, saved after every jack
// so a closed window or a crash never loses work, and read back so a walk can be resumed.
package walk

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jacktrace-dev/jacktrace/internal/report"
)

// Header is the CSV header row. Columns are only ever added at the end, so older files resume.
var Header = []string{
	"jack", "status", "switch", "port", "port_description", "vlan", "voice_vlan",
	"mgmt_ip", "poe_w", "link", "model", "via", "adapter", "heard_at", "note",
}

// Status values.
const (
	StatusFound   = "found"
	StatusNothing = "no switch heard"
)

// Row is one jack in the audit.
type Row struct {
	Jack            string
	Status          string
	Switch          string
	Port            string
	PortDescription string
	VLAN            string
	VoiceVLAN       string
	ManagementIP    string
	PoEWatts        string
	Link            string
	Model           string
	Via             string
	Adapter         string
	HeardAt         string
	Note            string
}

func (r Row) fields() []string {
	return []string{r.Jack, r.Status, r.Switch, r.Port, r.PortDescription, r.VLAN, r.VoiceVLAN,
		r.ManagementIP, r.PoEWatts, r.Link, r.Model, r.Via, r.Adapter, r.HeardAt, r.Note}
}

func rowFrom(f []string) Row {
	get := func(i int) string {
		if i < len(f) {
			return unescape(f[i])
		}
		return ""
	}
	return Row{get(0), get(1), get(2), get(3), get(4), get(5), get(6), get(7), get(8), get(9),
		get(10), get(11), get(12), get(13), get(14)}
}

// FromPort builds a row from a merged result.
func FromPort(jack string, p report.Port, at time.Time) Row {
	r := Row{
		Jack:            jack,
		Status:          StatusFound,
		Switch:          p.Switch,
		Port:            p.PortID,
		PortDescription: p.Description,
		ManagementIP:    p.ManagementIP,
		Link:            p.Link,
		Model:           p.Model,
		Via:             p.ViaText(),
		Adapter:         report.ShortLabel(p.Adapter),
		HeardAt:         at.Format("2006-01-02 15:04:05"),
	}
	if p.NativeVLAN > 0 {
		r.VLAN = strconv.Itoa(p.NativeVLAN)
	}
	if p.VoiceVLAN > 0 {
		r.VoiceVLAN = strconv.Itoa(p.VoiceVLAN)
	}
	if p.PoEWatts > 0 {
		r.PoEWatts = strconv.FormatFloat(p.PoEWatts, 'f', -1, 64)
	}
	return r
}

// Nothing is the row for a jack where no switch answered.
func Nothing(jack string, at time.Time) Row {
	return Row{Jack: jack, Status: StatusNothing, HeardAt: at.Format("2006-01-02 15:04:05")}
}

// SamePort reports whether two rows point at the same switch port.
func (r Row) SamePort(o Row) bool {
	return r.Status == StatusFound && o.Status == StatusFound &&
		strings.EqualFold(r.Switch, o.Switch) && strings.EqualFold(r.Port, o.Port)
}

// Audit is the rows of one walk, in the order jacks were traced.
type Audit struct {
	Path string
	Rows []Row
}

// Open loads an existing audit file, or starts an empty one if it doesn't exist yet.
func Open(path string) (*Audit, error) {
	a := &Audit{Path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	data = bytes.TrimPrefix(data, bom)
	recs, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%s isn't a JackTrace walk file I can read: %w", filepath.Base(path), err)
	}
	for i, rec := range recs {
		if i == 0 {
			if len(rec) == 0 || rec[0] != Header[0] {
				return nil, fmt.Errorf("%s doesn't look like a JackTrace walk file (first column should be %q); pick a new file name", filepath.Base(path), Header[0])
			}
			continue
		}
		if len(rec) > 0 && strings.TrimSpace(rec[0]) != "" {
			a.Rows = append(a.Rows, rowFrom(rec))
		}
	}
	return a, nil
}

// Duplicate returns the earlier jack recorded on the same switch port as r, if any.
func (a *Audit) Duplicate(r Row) (string, bool) {
	for _, o := range a.Rows {
		if o.Jack != r.Jack && o.SamePort(r) {
			return o.Jack, true
		}
	}
	return "", false
}

// Put records rows for a jack, replacing any rows already recorded under that label
// (so a redo overwrites rather than adds).
func (a *Audit) Put(jack string, rows ...Row) {
	var kept []Row
	replaced := -1
	for i, r := range a.Rows {
		if r.Jack == jack {
			if replaced < 0 {
				replaced = i
			}
			continue
		}
		kept = append(kept, r)
	}
	if replaced < 0 || replaced > len(kept) {
		a.Rows = append(kept, rows...)
		return
	}
	// Keep the jack where it was in the walk order.
	a.Rows = append(kept[:replaced:replaced], append(rows, kept[replaced:]...)...)
}

// Last is the most recently recorded jack label, or "".
func (a *Audit) Last() string {
	if len(a.Rows) == 0 {
		return ""
	}
	return a.Rows[len(a.Rows)-1].Jack
}

// Jacks counts distinct jack labels.
func (a *Audit) Jacks() int {
	seen := map[string]bool{}
	for _, r := range a.Rows {
		seen[r.Jack] = true
	}
	return len(seen)
}

// bom makes Excel open the file as UTF-8 instead of guessing a legacy code page.
var bom = []byte{0xEF, 0xBB, 0xBF}

// Save writes the whole file to a temporary file next to it and renames it into place, so the
// audit on disk is always complete. If Excel has the file open the rename fails; the caller keeps
// the rows in memory and tries again after the next jack.
func (a *Audit) Save() error {
	var buf bytes.Buffer
	buf.Write(bom)
	w := csv.NewWriter(&buf)
	w.UseCRLF = true // Windows line endings, for Excel and Notepad
	w.Write(Header)
	for _, r := range a.Rows {
		f := r.fields()
		for i := range f {
			f[i] = escape(f[i])
		}
		w.Write(f)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}

	dir := filepath.Dir(a.Path)
	tmp, err := os.CreateTemp(dir, ".jacktrace-walk-*.csv")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := io.Copy(tmp, &buf); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), a.Path)
}

// escape stops spreadsheet formula injection: a switch can name itself "=HYPERLINK(...)", and
// Excel would run it. Cells starting with a formula character get a leading apostrophe, which
// Excel hides and treats as "this is text".
func escape(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func unescape(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

var (
	trailingLetter = regexp.MustCompile(`^(.*\d)([A-Za-z])$`)
	lastNumber     = regexp.MustCompile(`^(.*?)(\d+)(\D*)$`)
)

// NextLabel suggests the label after this one, the way jacks are usually numbered:
// "R114-09" → "R114-10", "2-114A" → "2-114B", "D7" → "D8". It returns "" when there's no
// obvious next ("Lobby", "2-114Z").
func NextLabel(label string) string {
	if m := trailingLetter.FindStringSubmatch(label); m != nil {
		if m[2] == "z" || m[2] == "Z" {
			return "" // past the last letter; let the tech type the next one
		}
		return m[1] + string(m[2][0]+1)
	}
	m := lastNumber.FindStringSubmatch(label)
	if m == nil {
		return ""
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return ""
	}
	next := strconv.Itoa(n + 1)
	if pad := len(m[2]) - len(next); pad > 0 {
		next = strings.Repeat("0", pad) + next
	}
	return m[1] + next + m[3]
}
