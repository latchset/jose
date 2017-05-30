jose-jwk-thp(1) -- Calculates the JWK thumbprint
================================================

## SYNOPSIS

`jose jwk thp` -i JWK [-H ALG] [-o THP]

## OVERVIEW

The `jose jwk thp` command calculates the thumbprint of one or more JWKs.

## OPTIONS

* `-i` JSON, `--input`=JSON :
  Parse JWK(Set) from JSON

* `-i` FILE, `--input`=FILE :
  Read JWK(Set) from FILE

* `-i` -, `--input`=- :
  Read JWK(Set) standard input

* `-H` HASH, `--hash`=HASH :
  Use the specified hash algorithm

* `-H` ?, `--hash`=? :
  List available hash algorithms

* `-o` FILE, `--output`=FILE :
  Write thumbprint(s) to FILE

* `-o` -, `--output`=- :
  Write thumbprint(s) to standard input

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-alg`(1),
`jose-jwk-gen`(1),
