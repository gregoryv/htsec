package htsec

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"golang.org/x/oauth2"
)

type Guard struct {
	// A short name for use during login
	Name string

	// Used for the oauth2 flow
	oauth2.Config

	// Used to read contact information once authorized
	NewSlip func(client *http.Client) (*Slip, error)

	sec *SecurityDetail
}

// newState returns a string GUARDNAME.RANDOM.SIGNATURE.DESTINATION
// using som private
func (g *Guard) newState(dest string) string {
	// see https://stackoverflow.com/questions/26132066/\
	//   what-is-the-purpose-of-the-state-parameter-in-oauth-authorization-request
	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	// both random value and the signature must be usable in a url
	random := hex.EncodeToString(randomBytes)
	signature := g.sec.sign(random)
	return g.Name + "." + random + "." + signature + "." + dest
}
