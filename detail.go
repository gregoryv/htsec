package htsec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
		return "", err
	}
	state, err := s.newState(name)
	if err != nil {
		return "", err
	}
	return g.AuthCodeURL(state), nil
}

// guard returns named service if included, error if not found.
func (s *Detail) guard(name string) (*Guard, error) {
	g, found := s.guards[name]
	if !found {
		err := fmt.Errorf("guard %v: %w", name, notFound)
		return nil, err
	}
	return g, nil
}

var notFound = fmt.Errorf("not found")

// newState returns a string GUARDNAME.RANDOM.SIGNATURE using som private
func (s *Detail) newState(guardname string) (string, error) {
	// see https://stackoverflow.com/questions/26132066/\
	//   what-is-the-purpose-of-the-state-parameter-in-oauth-authorization-request
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	// both random value and the signature must be usable in a url
	random := hex.EncodeToString(randomBytes)
	signature := s.sign(random)
	return guardname + "." + random + "." + signature, nil
}

func (s *Detail) Authorize(ctx context.Context, r *http.Request) (*Slip, error) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	if err := s.verify(state); err != nil {
		return nil, err
	}
	// which auth service was used
	auth, err := s.guard(s.parseUse(state))
	if err != nil {
		return nil, err
	}
	// get the token
	token, err := auth.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	client := auth.Client(ctx, token)
	// get user information from the Auth service
	contact, err := auth.Contact(client)
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

// verify USE.RANDOM.SIGNATURE
func (s *Detail) verify(state string) error {
	parts := strings.Split(state, ".")
	if len(parts) != 3 {
		return fmt.Errorf("state: invalid format")
	}
	signature := s.sign(parts[1])
	if signature != parts[2] {
		return fmt.Errorf("state: invalid signature")
	}
	return nil
}

func (s *Detail) sign(random string) string {
	hash := sha256.New()
	hash.Write([]byte(random))
	hash.Write(s.PrivateKey)
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func (s *Detail) parseUse(state string) string {
	i := strings.Index(state, ".")
	if i < 0 {
		return ""
	}
	return state[:i]
}
