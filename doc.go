/*
Package htsec provides security detail for your endpoints.

In the oauth2 flow the state is

	GUARDNAME.RANDOM.SIGNATURE.DESTINATION

The random value and signature are verified using the security detail
private key.

The destination part can be used by you as a way to redirect users to
whatever they wanted to get in the first place.
*/
package htsec
