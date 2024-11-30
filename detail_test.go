package htsec

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestDetail_GuardURL(t *testing.T) {
	sec := NewDetail(
		&Guard{Name: "a", Config: &oauth2.Config{}},
	)
	if _, err := sec.GuardURL("a"); err != nil {
		t.Error(err)
	}
	if _, err := sec.GuardURL("john"); err == nil {
		t.Error("unknown guard should fail")
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
