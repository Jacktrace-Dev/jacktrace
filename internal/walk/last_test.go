package walk

import "testing"

func TestLast(t *testing.T) {
	cases := []struct {
		rows []Row
		want string
	}{
		{nil, ""},
		{[]Row{{Jack: "R114-01"}}, "R114-01"},
		{[]Row{{Jack: "R114-01"}, {Jack: "R114-02"}, {Jack: "R114-03"}}, "R114-03"},
	}
	for _, tc := range cases {
		a := &Audit{Rows: tc.rows}
		if got := a.Last(); got != tc.want {
			t.Errorf("Last() with %d rows = %q, want %q", len(tc.rows), got, tc.want)
		}
	}
}
