package htsec

import "golang.org/x/oauth2"

type Slip struct {
	State   string
	Token   *oauth2.Token
	Contact *Contact
}
