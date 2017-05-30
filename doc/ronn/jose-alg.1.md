jose-alg(1) -- Lists all supported algorithms
====================================================================

## SYNOPSIS

`jose alg` [-k KIND]

## OVERVIEW

The `jose alg` command lists the algorithms supported by all `jose` commands.
When no options are provided, all algorithms are listed. If one or more `-k`
options are provided, only the kinds of algorithms requested will be shown.

## OPTIONS

* `-k` _KIND_, `--kind`=_KIND_ :
  Restrict algorithm list to a certain kind

* `-k` ?, `--kind`=? :
  List valid algorithm kinds

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;
