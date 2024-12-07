package htsec

import "testing"

func TestSlip_Destination(t *testing.T) {
	s := Slip{State: "a.b"} // invalid state
	s.Destination()

	s.State = "a.b.c.d"
	exp := "d"
	if got := s.Destination(); got != exp {
		t.Errorf("got %q, expected %s", got, exp)
	}
}
