package htsec

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func NewDetail(guards ...*Guard) *Detail {
	s := Detail{
		PrivateKey: make([]byte, 32),
		guards:     make(map[string]*Guard),
	}
	for _, gate := range guards {
		name := domainName(gate.Endpoint.AuthURL)
		s.guards[name] = gate
	}
	_, _ = rand.Read(s.PrivateKey)
	return &s
}

type Detail struct {
	PrivateKey []byte
	guards     map[string]*Guard
}

func domainName(uri string) string {
	v, err := url.Parse(uri)
	if err != nil {
		panic(err.Error())
	}
	parts := strings.Split(v.Hostname(), ".")
	return parts[len(parts)-2]
}

// GuardURL returns url to the gate.
func (s *Detail) GuardURL(name string) (string, error) {
	svc, err := s.gate(name)
	if err != nil {
		return "", err
	}
	state, err := s.newState(name)
	if err != nil {
		return "", err
	}
	return svc.AuthCodeURL(state), nil
}

// Gate returns named service if included, error if not found.
func (s *Detail) gate(name string) (*Guard, error) {
	a, found := s.guards[name]
	if !found {
		err := fmt.Errorf("Secure.AuthService %v: %w", name, notFound)
		return nil, err
	}
	return a, nil
}

var notFound = fmt.Errorf("not found")

// NewState returns a string use.RANDOM.SIGNATURE using som private
func (s *Detail) newState(use string) (string, error) {
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
	return use + "." + random + "." + signature, nil
}

func (s *Detail) Authorize(ctx context.Context, r *http.Request) (*Slip, error) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	if err := s.verify(state); err != nil {
		return nil, err
	}
	// which auth service was used
	auth, err := s.gate(s.parseUse(state))
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
