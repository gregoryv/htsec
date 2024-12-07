[gregoryv/htsec](https://pkg.go.dev/github.com/gregoryv/htsec) provides handler security using oauth2

![](security_detail.svg)

In the oauth2 flow the state is

  GUARDNAME.RANDOM.SIGNATURE.DESTINATION

The random value and signature are verified using the security detail
private key.

The destination part can be used by you as a way to redirect users to
whatever they wanted to get in the first place.


## Quick start

    go get github.com/gregoryv/htsec
	
