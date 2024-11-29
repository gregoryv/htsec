package htsec_test

import (
	"fmt"

	"github.com/gregoryv/htsec"
	"github.com/gregoryv/htsec/github"
	"github.com/gregoryv/htsec/google"
)

func ExampleDetail() {
	sec := htsec.NewDetail(
		github.Guard(),
		google.Guard(),
	)

	url, _ := sec.Guard("google").URL()
	fmt.Println(url[:104] + "...") // exclude signed random part

	url, _ = sec.Guard("github").URL()
	fmt.Println(url[:83] + "...")
	// output:
	// https://accounts.google.com/o/oauth2/auth?client_id=&response_type=code&scope=profile+email&state=google...
	// https://github.com/login/oauth/authorize?client_id=&response_type=code&state=github...
}
