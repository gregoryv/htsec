package htsec

import "testing"

func TestSlip_Dest(t *testing.T) {
	s := Slip{State: "a.b"} // invalid state
	s.Dest()

	s.State = "a.b.c.d"
	exp := "d"
	if got := s.Dest(); got != exp {
		t.Errorf("got %q, expected %s", got, exp)
	}
}
