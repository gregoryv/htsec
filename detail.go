package htsec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

func NewDetail(guards ...*Guard) *Detail {
	s := Detail{
		PrivateKey: make([]byte, 32),
		guards:     make(map[string]*Guard),
	}
	for _, g := range guards {
		g.sec = &s
		s.guards[g.Name] = g
	}
	_, _ = rand.Read(s.PrivateKey)
	return &s
}

type Detail struct {
	PrivateKey []byte
	guards     map[string]*Guard
}

// GuardURL returns url to the gate.
func (s *Detail) GuardURL(name string) (string, error) {
	g, err := s.guard(name)
	if err != nil {
		return "", fmt.Errorf("GuardURL: %w", err)
	}
	return g.url()
}

func (s *Detail) Authorize(ctx context.Context, r *http.Request) (*Slip, error) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	g, err := s.verify(state)
	if err != nil {
		return nil, err
	}
	// get the token
	token, err := g.Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	client := g.Config.Client(ctx, token)
	// get user information from the Auth service
	contact, err := g.Contact(client)
	if err != nil {
		return nil, err
	}
	slip := Slip{
		State:   state,
		Token:   token,
		Contact: contact,
	}
	return &slip, nil
}

// guard returns named service if included, error if not found.
func (s *Detail) guard(name string) (*Guard, error) {
	g, found := s.guards[name]
	if !found {
		return nil, fmt.Errorf("guard %s: %w", name, notFound)
	}
	return g, nil
}

var notFound = fmt.Errorf("not found")

// verify GUARDNAME.RAND.SIGNATURE
func (s *Detail) verify(state string) (*Guard, error) {
	parts := strings.Split(state, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: invalid format", ErrState)
	}
	// check if guard is part of the security detail
	name := parts[0]
	g, err := s.guard(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrState, err)
	}
	signature := s.sign(parts[1])
	if signature != parts[2] {
		return nil, fmt.Errorf("%w: invalid signature", ErrState)
	}
	return g, nil
}

func (s *Detail) sign(random string) string {
	hash := sha256.New()
	hash.Write([]byte(random))
	hash.Write(s.PrivateKey)
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

var (
	// ErrState indicates something in the state data is invalid
	ErrState = fmt.Errorf("state")
)
