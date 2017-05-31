jose(1) -- Toolkit for performing JSON Object Signing and Encryption
====================================================================

## SYNOPSIS

`jose alg` [-k KIND]

`jose b64 dec` -i B64 [-O BIN]

`jose b64 enc` -I BIN [-o B64]

`jose jwe dec` -i JWE [-I CT] -k JWK [-p] [-O PT]

`jose jwe enc` [-i JWE] -I PT -k JWK [-p] [-r RCP] [-o JWE] [-O CT] [-c]

`jose jwe fmt` -i JWE [-I CT] [-o JWE] [-O CT] [-c]

`jose jwk exc` [-i JWK] -l JWK -r JWK [-o JWK]

`jose jwk gen` -i JWK [-o JWK]

`jose jwk pub` -i JWK [-o JWK]

`jose jwk thp` -i JWK [-a ALG] [-o THP]

`jose jwk use` -i JWK [-a] [-r] -u OP

`jose jws fmt` -i JWS [-I PAY] [-o JWS] [-O PAY] [-c]

`jose jws sig` [-i JWS] [-I PAY] [-s SIG] -k JWK [-o JWS] [-O PAY] [-c]

`jose jws ver` -i JWS [-I PAY] -k JWK [-O PAY] [-a]

## OVERVIEW

José is a C-language implementation of the Javascript Object Signing and
Encryption standards. Specifically, José aims towards implementing the
following standards:

* RFC 7515 - JSON Web Signature (JWS)
* RFC 7516 - JSON Web Encryption (JWE)
* RFC 7517 - JSON Web Key (JWK)
* RFC 7518 - JSON Web Algorithms (JWA)
* RFC 7519 - JSON Web Token (JWT)
* RFC 7520 - Examples of Protecting Content Using JOSE
* RFC 7638 - JSON Web Key (JWK) Thumbprint


The José command line utility provides facilities for the following:

* URL-safe Base64 Encoding & Decoding
* Key Generation and Management
* Encryption & Decryption
* Signing & Verification

## AUTHOR

Nathaniel McCallum &lt;npmccallum@redhat.com&gt;

## SEE ALSO

`jose-alg`(1),
`jose-b64-dec`(1),
`jose-b64-enc`(1),
`jose-jwe-dec`(1),
`jose-jwe-enc`(1),
`jose-jwe-fmt`(1),
`jose-jwk-exc`(1),
`jose-jwk-gen`(1),
`jose-jwk-pub`(1),
`jose-jwk-thp`(1),
`jose-jwk-use`(1),
`jose-jws-fmt`(1),
`jose-jws-sig`(1),
`jose-jws-ver`(1)
