jose-jwk-exc(1) -- Performs a key exchange using the two input keys
===================================================================

## SYNOPSIS

`jose jwk exc` [-i JWK] -l JWK -r JWK [-o JWK]

## OVERVIEW

The `jose jwk exc` command performs a key exchange using the two input keys
and provides the result of the exchange as output. The user can specify a JWK
template as input and the specified properties will appear in the output JWK
unmodified.

A key exchange requires two keys:

1. The local key, which contains private key material.
2. The remote key, which contains public key material.

## OPTIONS

* `-i` _JSON_, `--input`=_JSON_ :
  Parse JWK template from JSON

* `-i` _FILE_, `--input`=_FILE_ :
  Read JWK template from FILE

* `-i` -, `--input`=- :
  Read JWK template from standard input

* `-o` _FILE_, `--output`=_FILE_ :
  Write JWK(Set) to FILE

* `-o` -, `--output`=- :
  Write JWK(Set) to standard input

* `-l` _FILE_, `--local`=_FILE_ :
  Read local JWK from FILE

* `-l` -, `--local`=- :
  Read local JWK from standard input

* `-r` _FILE_, `--remote`=_FILE_ :
  Read remote JWK from FILE

* `-r` -, `--remote`=- :
  Read remote JWK from standard input

## EXAMPLES

Perform a key exchange:

    $ jose jwk gen -i '{"alg":"ECDH"}' -o local.jwk
    $ jose jwk gen -i '{"alg":"ECDH"}' | jose jwk pub -i- -o remote.jwk
    $ jose jwk exc -l local.jwk -r remote.jwk -o exchanged.jwk

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-alg`(1),
`jose-jwk-exc`(1),
`jose-jwk-gen`(1),
`jose-jwk-pub`(1)
