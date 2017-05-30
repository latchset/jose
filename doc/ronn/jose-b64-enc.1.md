jose-b64-enc(1) -- Encodes binary data to URL-safe Base64
====================================================================

## SYNOPSIS

`jose b64 enc` `-I` BIN [-o B64]

## OVERVIEW

The `jose b64 enc` command encodes binary data to URL-safe Base64 format.

## OPTIONS

* `-I` _FILE_, `--binary`=_FILE_ :
  Read binary data from FILE

* `-I` -, `--binary`=- :
  Read binary data from standard input

* `-o` _FILE_, `--base64`=_FILE_ :
  Write Base64 (URL-safe) to FILE

* `-o` -, `--base64`=- :
  Write Base64 (URL-safe) to standard output

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-b64-dec`(1)
