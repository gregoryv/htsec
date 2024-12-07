package htsec

import (
	"strings"

	"golang.org/x/oauth2"
)

type Slip struct {
	// GUARDNAME.RANDOM.SIGNATURE.DESTINATION
	//
	// GUARNAME - identifies the guard used
	// RANDOM - a random server side string used during verification
	// SIGNATURE - signature of the state based on the security detail private key
	// DESTINATION - the protected path you wanted to reach
	State string
	Token *oauth2.Token

	// Name of the authorized account
	Name string

	// Email of the authorized account
	Email string
}

// Destination returns the DESTINATION part of the state or empty if
// invalid.
func (s *Slip) Destination() string {
	parts := strings.Split(s.State, ".")
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}
