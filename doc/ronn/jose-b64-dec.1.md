jose-b64-dec(1) -- Decodes URL-safe Base64 data to binary
====================================================================

## SYNOPSIS

`jose b64 dec` -i B64 [-O BIN]

## OVERVIEW

The `jose b64 dec` command decodes URL-safe Base64 data to binary format.

## OPTIONS

* `-i` _FILE_, `--base64`=_FILE_ :
  Read Base64 (URL-safe) data from FILE

* `-i` -, `--base64`=- :
  Read Base64 (URL-safe) data from standard input

* `-O` _FILE_, `--binary`=_FILE_ :
  Write binary data to FILE

* `-O` -, `--binary`=- :
  Write binary data to standard output

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-b64-enc`(1)
