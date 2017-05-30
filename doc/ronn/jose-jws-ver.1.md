jose-jws-ver(1) -- Verifies a JWS using the supplied JWKs
=========================================================

## SYNOPSIS

`jose jws ver` -i JWS [-I PAY] -k JWK [-a] [-O PAY]

## OVERVIEW

The `jose jws ver` command verifies a signature over a payload using one or
more JWKs. When specifying more than one JWK (`-k`), the program will succeed
when any of the provided JWKs successfully verify a signature. Alternatively,
if the `-a` option is given, the program will succeed only when all JWKs
successfully verify a signature.

If the JWS is a detached JWS, meaning that the payload is stored in binary
form external to the JWS itself, the payload can be loaded using the `-I`
parameter.

Please note that, when specifying the `-O` option to output the payload,
the payload is output whether or not the signature validates. Therefore,
you must check the return value of the command before trusting the data.

## OPTIONS

* `-i` _JSON_, `--input`=_JSON_ :
  Parse JWS from JSON

* `-i` _FILE_, `--input`=_FILE_ :
  Read JWS from FILE

* `-i` -, `--input`=- :
  Read JWS from standard input

* `-I` _FILE_, `--detached`=_FILE_ :
  Read decoded payload from FILE

* `-I` -, `--detached`=- :
  Read decoded payload from standard input

* `-k` _FILE_, `--key`=_FILE_ :
  Read JWK(Set) from FILE

* `-k` -, `--key`=- :
  Read JWK(Set) from standard input

* `-O` _FILE_, `--detach`=_FILE_ :
  Decode payload to FILE

* `-O` -, `--detach`=- :
  Decode payload to standard output

* `-a`, `--all` :
  Ensure the JWS validates with all keys

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-jws-fmt`(1),
`jose-jws-sig`(1)
