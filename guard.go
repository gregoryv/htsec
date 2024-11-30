package htsec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

type Guard struct {
	// A short name for use during login
	Name string

	// Used for the oauth2 flow
	*oauth2.Config

	// Used to read contact information once authorized
	Contact func(client *http.Client) (*Contact, error)

	sec *Detail
}

// newState returns a string GUARDNAME.RANDOM.SIGNATURE using som private
func (g *Guard) newState() (string, error) {
	// see https://stackoverflow.com/questions/26132066/\
	//   what-is-the-purpose-of-the-state-parameter-in-oauth-authorization-request
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	// both random value and the signature must be usable in a url
	random := hex.EncodeToString(randomBytes)
	signature := g.sec.sign(random)
	return g.Name + "." + random + "." + signature, nil
}

// url returns url including state using oauth2 AuthCodeURL
func (g *Guard) url() (string, error) {
	state, err := g.newState()
	if err != nil {
		return "", err
	}
	if g.Config == nil {
		return "", fmt.Errorf("%v: missing Config", g)
	}
	return g.AuthCodeURL(state), nil
}

func (g *Guard) String() string {
	return fmt.Sprintf("guard %s", g.Name)
}
