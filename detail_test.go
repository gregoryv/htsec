package htsec

import (
	"context"
	"fmt"
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
	path := "/callback?state=NAME.RAND.SIGN"
	r, _ := http.NewRequest("GET", path, http.NoBody)

	_, err := sec.Authorize(ctx, r)
	if err := contains(err.Error(), "NAME"); err != nil {
		t.Error("error message:", err)
	}
}

func contains(got string, expect ...string) error {
	var miss []string
	for _, exp := range expect {
		if !strings.Contains(got, exp) {
			miss = append(miss, exp)
		}
	}
	if len(miss) > 0 {
		return fmt.Errorf("missing %q", miss)
	}
	return nil
}
