package htsec_test

import (
	"fmt"
	"net/http"

	"github.com/gregoryv/htsec"
	"github.com/gregoryv/htsec/github"
	"github.com/gregoryv/htsec/google"
)

func ExampleDetail() {
	sec := htsec.NewDetail(
		github.Guard(),
		google.Guard(),
	)
	h := NewRouter(sec)
	http.ListenAndServe(":8080", h)
}

func NewRouter(sec *htsec.Detail) *http.ServeMux {
	mx := http.NewServeMux()
	mx.HandleFunc("/{$}", frontpage)
	mx.Handle("/login", login(sec))
	// reuse the same callback endpoint
	mx.Handle("/oauth/redirect", callback(sec))
	// everything else is private
	mx.Handle("/", private())
	return mx
}

func frontpage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `Login: <a href="/login?use=github">github</a>,
            <a href="/login?use=google>google></a>`,
	)
}

func login(sec *htsec.Detail) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("use")
		url, err := sec.Guard(name).URL()
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func callback(sec *htsec.Detail) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		slip, err := sec.Authorize(ctx, r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// setup session ...
		_ = slip.Contact
		http.Redirect(w, r, "/inside", http.StatusSeeOther)
	}
}

func private() http.Handler {
	mx := http.NewServeMux()
	mx.HandleFunc("/inside", inside)
	return protect(mx)
}

func protect(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// verify session, see callback
		//if err := sessionValid(r); err != nil {
		//	http.Redirect(w, r, "/", http.StatusSeeOther)
		//  return
		//}
		next.ServeHTTP(w, r)
	}
}

func inside(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "You are inside!")
}
