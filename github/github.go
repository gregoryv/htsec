package github

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gregoryv/htsec"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

func Guard() *htsec.Guard {
	return &htsec.Guard{
		Config: &oauth2.Config{
			RedirectURL:  os.Getenv("OAUTH_GITHUB_REDIRECT_URI"),
			ClientID:     os.Getenv("OAUTH_GITHUB_CLIENTID"),
			ClientSecret: os.Getenv("OAUTH_GITHUB_SECRET"),
			Endpoint:     endpoints.GitHub,
		},
		Contact: Contact,
	}
}

func Contact(c *http.Client) (*htsec.Contact, error) {
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
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}
