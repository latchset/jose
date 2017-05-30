jose-jwk-gen(1) -- Creates a random JWK for each input JWK template
===================================================================

## SYNOPSIS

`jose jwk gen` -i JWK [-o JWK]

## OVERVIEW

The `jose jwk gen` command generates a key from one or more JWK(Set) templates.
If a single template is given as input, a single JWK will be output. However,
if multiple templates are given as input, a single JWKSet will be output
containing all the keys.

The best way to generate a key is to use an algorithm, for example:

    $ jose jwk gen -i '{"alg":"HS256"}' ...
    $ jose jwk gen -i '{"alg":"RS256"}' ...
    $ jose jwk gen -i '{"alg":"ES256"}' ...

Note that when generating from an algorithm, an appropriate "key_ops"
parameter is also emitted automatically.

However, you may also specify key parameters:

    $ jose jwk gen -i '{"kty":"EC","crv":"P-256"}' ...
    $ jose jwk gen -i '{"kty":"oct","bytes":32}' ...
    $ jose jwk gen -i '{"kty":"RSA","bits":4096}' ...

Note that the "bytes" and "bits" parameters are non-standard, so they will
be removed from the output JWK(Set).

## OPTIONS

* `-i` _JSON_, `--input`=_JSON_ :
  Parse JWK(Set) template from JSON

* `-i` _FILE_, `--input`=_FILE_ :
  Read JWK(Set) template from FILE

* `-i` -, `--input`=- :
  Read JWK(Set) template from standard input

* `-o` _FILE_, `--output`=_FILE_ :
  Write JWK(Set) to FILE

* `-o` -, `--output`=- :
  Write JWK(Set) to standard input

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-alg`(1),
`jose-jwe-dec`(1),
`jose-jwe-enc`(1),
`jose-jwk-exc`(1),
`jose-jwk-pub`(1),
`jose-jwk-thp`(1),
`jose-jwk-use`(1),
`jose-jws-sig`(1),
`jose-jws-ver`(1),
