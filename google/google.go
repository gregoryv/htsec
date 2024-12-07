// Package google provides a google.com guard
package google

import (
	"context"
	"net/http"
	"os"

	"github.com/gregoryv/htsec"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

// Guard uses environment variables
//
//	OAUTH_GOOGLE_REDIRECT_URL="..."
//	OAUTH_GOOGLE_CLIENT_ID="..."
//	OAUTH_GOOGLE_SECRET="...
func Guard() *htsec.Guard {
	return &htsec.Guard{
		Name: "google",
		Config: oauth2.Config{
			RedirectURL:  os.Getenv("OAUTH_GOOGLE_REDIRECT_URL"),
			ClientID:     os.Getenv("OAUTH_GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("OAUTH_GOOGLE_SECRET"),
			Scopes:       []string{"profile", "email"},
			Endpoint:     endpoints.Google,
		},
		NewSlip: newSlip,
	}
}

func newSlip(c *http.Client) (*htsec.Slip, error) {
	ctx := context.Background()
	service, err := people.NewService(ctx,
		option.WithHTTPClient(c),
	)
	if err != nil {
		return nil, err
	}

	profile, err := service.People.Get("people/me").PersonFields(
		"names,emailAddresses",
	).Do()
	if err != nil {
		return nil, err
	}

	var slip htsec.Slip
	if len(profile.EmailAddresses) > 0 {
		slip.Email = profile.EmailAddresses[0].Value
	}
	if len(profile.Names) > 0 {
		n := profile.Names[0]
		slip.Name = n.GivenName + " " + n.FamilyName
		if slip.Name == "" {
			slip.Name = n.DisplayName
		}
	}
	return &slip, nil
}
