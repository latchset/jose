jose-jwk-pub(1) -- Cleans private keys from a JWK
=================================================

## SYNOPSIS

`jose jwk pub` -i JWK [-o JWK]

## OVERVIEW

The `jose jwk pub` command removes all private key material from one or more
JWK(Set) inputs. The output will contain only public key material.

If the JWK contains the "key_ops" property, it will be automatically adjusted
to include only operations relevant to public keys.

## OPTIONS

* `-i` _JSON_, `--input`=_JSON_ :
  Parse JWK(Set) from JSON

* `-i` _FILE_, `--input`=_FILE_ :
  Read JWK(Set) from FILE

* `-i` -, `--input`=- :
  Read JWK(Set) from standard input

* `-o` _FILE_, `--output`=_FILE_ :
  Write JWK(Set) to FILE

* `-o` -, `--output`=- :
  Write JWK(Set) to standard input

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-alg`(1),
`jose-jwe-enc`(1),
`jose-jwk-exc`(1),
`jose-jwk-gen`(1),
`jose-jwk-thp`(1),
`jose-jwk-use`(1),
`jose-jws-ver`(1)
