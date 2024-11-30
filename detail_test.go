package htsec

import (
	"testing"
)

func TestDetail_Guard(t *testing.T) {
	s := NewDetail(
		&Guard{Name: "a"},
		&Guard{Name: "b"},
	)
	if g := s.Guard("a"); g.Name != "a" {
		t.Error("named guard should exist")
	}
	if g := s.Guard("john"); g.Name != "unknown" {
		t.Error("invalid unknown guard", g.Name)
	}
}
