jose-pbkdf2(1) -- Runs PBKDF2 over input
========================================

## SYNOPSIS

`jose pbkdf2` -i DATA [-I ITER] [-a ALG] [-s SALT]

## OVERVIEW

The `jose pbkdf2` command runs PBKDF2 over input text to generate keying
material resistant to brute force attacks with configurable parameters.

## OPTIONS

* `-i` _FILE_, `--input`=_FILE_ :
  Read input data from FILE

* `-i` -, `--input`=- :
  Read input data from standard input

* `-I` _ITER_, `--iter`=_ITER_ :
  Set PBKDF2 iteration count to ITER

* `-a` _ALG_, `--algorithm`=_ALG_ :
  Use _ALG_ as the underlying hash algorithm for PBKDF2

* `-s` _SALT_, `--salt`=_SALT_ :
  Use _SALT_ as a salt input to the PBKDF2 instead of the default salt value

## EXAMPLES

Use SHA-256 as underlying hash algorithm for PBKDF2 over user supplied text:

    $ echo "User supplied strong passphrase" | jose pbkdf2 -i- -a S256 > passdata.out

## AUTHOR

Max Tottenham &lt;mtottenh@gmail.com&gt;
