package htsec

import (
	"strings"

	"golang.org/x/oauth2"
)

type Slip struct {
	State string
	Token *oauth2.Token

	Name  string
	Email string
}

func (s *Slip) Dest() string {
	parts := strings.Split(s.State, ".")
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}
