jose-jwe-enc(1) -- Encrypts plaintext using one or more JWK/password
====================================================================

## SYNOPSIS

`jose jwe enc` [-i JWE] -I PT -k JWK [-p] [-r RCP] [-o JWE] [-O CT] [-c]

## OVERVIEW

The `jose jwe enc` command encrypts data using one or more JWK (`-k`) or
password (`-p`). When specifying more than one JWK or password, decryption
will succeed with any one of the provided keys.

A detached JWE can be created by specifying the `-O` option. In this case,
the decoded ciphertext will be written to the output specified and will not
be included in the JWE.

If only one key is used (`-k` or `-p`), the resulting JWE may be output in
JWE Compact Serialization by using the `-c` option.

This command uses a template based approach for constructing a JWE. You can
specify templates of the JWE itself (`-i`) or for the JWE Recipient Object
(`-r`). Attributes specified in either of these templates will appear
unmodified in the output. One exception to this rule is that the JWE Protected
Header should be specified in its decoded form in the template. This command
will automatically encode it as part of the encryption process.

If you specify a JOSE Header Parameter that affects the construction of the
JWE, this command will attempt to behave according to this parameter as if it
were configuration. For example, specifying the "zip" parameter in the JWE
Protected Header will cause the plaintext to be compressed before encryption.

## OPTIONS

*  `-i` _JSON_, `--input`=_JSON_ :
  Parse JWE from JSON

*  `-i` _FILE_, `--input`=_FILE_ :
  Read JWE from FILE

*  `-i` -, `--input`=-:
  Read JWE from standard input

*  `-I` _FILE_, `--detached`=_FILE_ :
  Read decoded ciphertext from FILE

*  `-I` -, `--detached`=- :
  Read decoded ciphertext from standard input

*  `-r` _FILE_, `--recipient`=_FILE_ :
  Read JWE recipient template from FILE

*  `-r` -, `--recipient`=- :
  Read JWE recipient template from standard input

*  `-k` _FILE_, `--key`=_FILE_ :
  Read JWK(Set) from FILE

*  `-k` -, `--key`=- :
  Read JWK(Set) from standard input

*  `-p`, `--password :
  Prompt for an encryption password

*  `-o` _FILE_, `--output`=_FILE_ :
  Write JWE to FILE

*  `-o` -, `--output`=- :
  Write JWE to stdout (default)

*  `-O` _FILE_, `--detach`=_FILE_ :
  Detach ciphertext and decode to FILE

*  `-O` -, `--detach`=- :
  Detach ciphertext and decode to standard output

*  `-c`, `--compact` :
  Output JWE using compact serialization

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-jwe-dec`(1),
`jose-jwe-fmt`(1)
