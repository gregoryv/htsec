/*
Package htsec provides security detail for your endpoints.

The security detail with it's guards is used to authorize requests.
Once authorized a slip with e.g. name, email and toke is returned for
further use.

In the oauth2 flow the state is

	GUARDNAME.RANDOM.SIGNATURE.DESTINATION

The random value, signature and security detail private key are used
to verify the state.

The destination part can be used by you as a way to redirect users to
whatever they wanted to get in the first place.
*/
package htsec
