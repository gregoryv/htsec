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

func Guard() *htsec.Guard {
	return &htsec.Guard{
		Name: "google",
		Config: &oauth2.Config{
			RedirectURL:  os.Getenv("OAUTH_GOOGLE_REDIRECT_URI"),
			ClientID:     os.Getenv("OAUTH_GOOGLE_CLIENTID"),
			ClientSecret: os.Getenv("OAUTH_GOOGLE_SECRET"),
			Scopes:       []string{"profile", "email"},
			Endpoint:     endpoints.Google,
		},
		Contact: Contact,
	}
}

func Contact(c *http.Client) (*htsec.Contact, error) {
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

	var u htsec.Contact
	if len(profile.EmailAddresses) > 0 {
		u.Email = profile.EmailAddresses[0].Value
	}
	if len(profile.Names) > 0 {
		n := profile.Names[0]
		u.Name = n.GivenName + " " + n.FamilyName
		if u.Name == "" {
			u.Name = n.DisplayName
		}
	}
	return &u, nil
}
