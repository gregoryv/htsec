package htsec

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestDetail_Guard(t *testing.T) {
	sec := NewDetail(
		&Guard{Name: "a"},
		&Guard{Name: "b"},
	)
	if g := sec.Guard("a"); g.Name != "a" {
		t.Error("named guard should exist")
	}
	if g := sec.Guard("john"); g.Name != "unknown" {
		t.Error("invalid unknown guard", g.Name)
	}
}

func TestDetail_Authorize(t *testing.T) {
	sec := NewDetail()
	ctx := context.Background()
	r, _ := http.NewRequest(
		"GET", "/callback?state=NAME.RAND.SIGN", http.NoBody,
	)

	_, err := sec.Authorize(ctx, r)
	if v := err.Error(); !strings.Contains(v, "NAME") {
		t.Error("expect error to contain the guard name", v)
	}
}
