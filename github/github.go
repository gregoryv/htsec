// Package github provides a github.com guard
package github

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gregoryv/htsec"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// Guard uses environment variables
//
//	OAUTH_GITHUB_REDIRECT_URL="..."
//	OAUTH_GITHUB_CLIENT_ID="..."
//	OAUTH_GITHUB_SECRET="...
func Guard() *htsec.Guard {
	return &htsec.Guard{
		Name: "github",
		Config: oauth2.Config{
			RedirectURL:  os.Getenv("OAUTH_GITHUB_REDIRECT_URL"),
			ClientID:     os.Getenv("OAUTH_GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("OAUTH_GITHUB_SECRET"),
			Endpoint:     endpoints.GitHub,
		},
		Contact: contact,
	}
}

func contact(c *http.Client) (*htsec.Contact, error) {
	r, _ := http.NewRequest(
		"GET", "https://api.github.com/user", nil,
	)
	r.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := c.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var u htsec.Contact
	err = json.NewDecoder(resp.Body).Decode(&u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
