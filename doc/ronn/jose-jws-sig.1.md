jose-jws-sig(1) -- Signs a payload using one or more JWKs
=========================================================

## SYNOPSIS

`jose jws sig` [-i JWS] [-I PAY] [-s SIG] -k JWK [-o JWS] [-O PAY] [-c]

## OVERVIEW

The `jose jws sig` command signs a payload using one or more JWKs. The payload
can be provided either in its decoded form (`-I`) or embedded in an existing
JWS ('-i').

A detached JWS can be created by specifying the `-O` option. In this case,
the decoded payload will be written to the output specified and will not be
included in the JWS.

If only one key is used (`-k`), the resulting JWS may be output in JWS Compact
Serialization by using the `-c` option.

This command uses a template based approach for constructing a JWS. You can
specify templates of the JWS itself (`-i`) or for the JWS Signature Object
(`-r`). Attributes specified in either of these templates will appear
unmodified in the output. One exception to this rule is that the JWS Protected
Header should be specified in its decoded form in the JWS Signature Object
template. This command will automatically encode it as part of the encryption
process.

It is possible to specify an existing JWS as the JWS template input (`-i`).
This allows the addition of new signatures to an existing JWS.

## OPTIONS

* `-i` _JSON_,  `--input`=_JSON_ :
  Parse JWS template from JSON

* `-i` _FILE_,  `--input`=_FILE_ :
  Read JWS template from FILE

* `-i` -, `--input`=- :
  Read JWS template from standard input

* `-I` _FILE_, `--detached`=_FILE_
  Read decoded payload from FILE

* `-I` -, `--detached`=- :
  Read decoded payload from standard input

* `-s` _JSON_, `--signature`=_JSON_ :
  Parse JWS signature template from JSON

* `-s` _FILE_, `--signature`=_FILE_ :
  Read JWS signature template from FILE

* `-s` -, `--signature`=- :
  Read JWS signature template standard input

* `-k` _FILE_, `--key`=_FILE_ :
  Read JWK(Set) from FILE

* `-k` -, `--key`=- :
  Read JWK(Set) from standard input

* `-o` _FILE_, `--output`=_FILE_ :
  Write JWS to FILE

* `-o` -, `--output`=- :
  Write JWS to stdout (default)

* `-O` _FILE_, `--detach`=_FILE_ :
  Detach payload and decode to FILE

* `-O` -, `--detach`=- :
  Detach payload and decode to standard output

* `-c`, `--compact` :
  Output JWS using compact serialization

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-jws-sig`(1),
`jose-jws-ver`(1)
