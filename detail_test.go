package htsec

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestDetail_GuardURL(t *testing.T) {
	sec := NewDetail(
		&Guard{Name: "a"},
	)
	if _, err := sec.GuardURL("a"); err != nil {
		t.Error(err)
	}
	if _, err := sec.GuardURL("john"); err == nil {
		t.Error("unknown guard should fail")
	}
}

func TestDetail_Authorize(t *testing.T) {
	g := &Guard{
		Name: "a",
		Config: oauth2.Config{
			RedirectURL:  "http://example.com/redirect",
			ClientID:     "abc",
			ClientSecret: "secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "http://127.0.0.1/auth",
				TokenURL: "http://127.0.0.1/token",
			},
		},
	}
	sec := NewDetail(g)
	ctx := context.Background()
	state := g.newState()
	path := "/callback?code=hepp&state=" + state
	r, _ := http.NewRequest("GET", path, http.NoBody)

	if _, err := sec.Authorize(ctx, r); err == nil {
		t.Error(err)
	}
}

func TestDetail_Authorize_stateErr(t *testing.T) {
	sec := NewDetail(
		&Guard{Name: "a"},
	)
	ctx := context.Background()
	cases := map[string]string{
		"x.RAND.SIGN": "x",
		"a.RAND.SIGN": "invalid signature",
		"a.b":         "invalid format",
	}
	for state, expect := range cases {
		t.Run(state, func(t *testing.T) {
			path := "/callback?state=" + state
			r, _ := http.NewRequest("GET", path, http.NoBody)

			_, err := sec.Authorize(ctx, r)
			if err := stateErr(err, expect); err != nil {
				t.Error(err)
			}
		})
	}
}

// ----------------------------------------

func stateErr(err error, expect ...string) error {
	if !errors.Is(err, ErrState) {
		return fmt.Errorf("expected error type %T", ErrState)
	}
	return contains(err.Error(), expect...)
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
