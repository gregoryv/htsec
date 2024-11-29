package htsec

import (
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
}
