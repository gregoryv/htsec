package htsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestSecurityDetail_GuardURL(t *testing.T) {
	sec := NewSecurityDetail(
		&Guard{Name: "a"},
	)
	if _, err := sec.GuardURL("a", "/mypath?x=2"); err != nil {
		t.Error(err)
	}
	if _, err := sec.GuardURL("john", "/"); err == nil {
		t.Error("unknown guard should fail")
	}
}

func TestSecurityDetail_Authorize(t *testing.T) {
	// fake oauth2 service
	mx := http.NewServeMux()
	mx.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "TOKEN",
		})
	})
	srv := httptest.NewServer(mx)
	defer srv.Close()

	g := newTestGuard(srv)
	sec := NewSecurityDetail(g)
	ctx := context.Background()
	state := g.newState("/")
	path := "/callback?code=hepp&state=" + state
	r, _ := http.NewRequest("GET", path, http.NoBody)

	if _, err := sec.Authorize(ctx, r); err != nil {
		t.Error(err)
	}
}

func TestSecurityDetail_Authorize_contactErr(t *testing.T) {
	// fake oauth2 service
	mx := http.NewServeMux()
	mx.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "TOKEN",
		})
	})
	srv := httptest.NewServer(mx)
	defer srv.Close()

	g := newTestGuard(srv)
	broken := fmt.Errorf("broken")
	g.NewSlip = func(*http.Client) (*Slip, error) {
		return nil, broken
	}
	sec := NewSecurityDetail(g)
	ctx := context.Background()
	state := g.newState("/")
	path := "/callback?code=hepp&state=" + state
	r, _ := http.NewRequest("GET", path, http.NoBody)

	if _, err := sec.Authorize(ctx, r); err != broken {
		t.Error(err)
	}
}

func TestSecurityDetail_Authorize_exchangeErr(t *testing.T) {
	// fake oauth2 service
	mx := http.NewServeMux()
	mx.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, "{}") // ie. missing access_token
	})
	srv := httptest.NewServer(mx)
	defer srv.Close()

	g := newTestGuard(srv)
	sec := NewSecurityDetail(g)
	ctx := context.Background()
	state := g.newState("/")
	path := "/callback?code=hepp&state=" + state
	r, _ := http.NewRequest("GET", path, http.NoBody)

	_, err := sec.Authorize(ctx, r)
	if err := contains(err.Error(), "missing access_token"); err != nil {
		t.Error(err)
	}
}

func newTestGuard(srv *httptest.Server) *Guard {
	return &Guard{
		Name: "a",
		Config: oauth2.Config{
			RedirectURL:  "...",
			ClientID:     "abc",
			ClientSecret: "secret",
			Endpoint: oauth2.Endpoint{
				AuthURL:  srv.URL + "/auth",
				TokenURL: srv.URL + "/token",
			},
		},
		NewSlip: func(c *http.Client) (*Slip, error) {
			return &Slip{Name: "John"}, nil
		},
	}
}

func TestSecurityDetail_Authorize_stateErr(t *testing.T) {
	sec := NewSecurityDetail(
		&Guard{Name: "a"},
	)
	ctx := context.Background()
	cases := map[string]string{
		"x.RAND.SIGN.DEST": "x",
		"a.RAND.SIGN.DEST": "invalid signature",
		"a.b":              "invalid format",
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
