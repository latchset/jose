jose-jwk-use(1) -- Validates a key for the specified use(s)
===========================================================

## SYNOPSIS

`jose jwk use` -i JWK [-a] [-r] -u OP

## OVERVIEW

The `jose jwk use` command validates one or more JWK(Set) inputs for a given
set of usages. This will be validated against the "use" and "key_ops"
properties of each JWK.

By default, if a JWK has no restrictions an operation will be allowed.
However, by specifying the `-r` option you can ensure that a JWK will not
be allowed unless it explicitly permits the option.

## OPTIONS

* `-i` _JSON_, `--input`=_JSON_ :
  Parse JWK(Set) from JSON

* `-i` _FILE_, `--input`=_FILE_ :
  Read JWK(Set) from FILE

* `-i` -, `--input`=- :
  Read JWK(Set) standard input

* `-u` sign, `--use`=sign :
  Validate the key for signing

* `-u` verify, `--use`=verify :
  Validate the key for verifying

* `-u` encrypt, `--use`=encrypt :
  Validate the key for encrypting

* `-u` decrypt, `--use`=decrypt :
  Validate the key for decrypting

* `-u` wrapKey, `--use`=wrapKey :
  Validate the key for wrapping

* `-u` unwrapKey, `--use`=unwrapKey :
  Validate the key for unwrapping

* `-u` deriveKey, `--use`=deriveKey :
  Validate the key for deriving keys

* `-u` deriveBits, `--use`=deriveBits :
  Validate the key for deriving bits

* `-a`, `--all` :
  Succeeds only if all operations are allowed

* `-r`, `--required` :
  Operations must be explicitly allowed

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-jwk-gen`(1)
