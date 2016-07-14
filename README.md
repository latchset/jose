# Welcome to José!

José is a C-language implementation of the Javascript Object Signing and
Encryption standards. Specifically, José aims towards implementing the
following standards:

  * RFC 7515 - JSON Web Signature (JWS)
  * RFC 7516 - JSON Web Encryption (JWE)
  * RFC 7517 - JSON Web Key (JWK)
  * RFC 7518 - JSON Web Algorithms (JWA)
  * RFC 7519 - JSON Web Token (JWT)
  * RFC 7520 - Examples of ... JOSE
  * RFC 7638 - JSON Web Key (JWK) Thumbprint

José is extensively tested against the RFC test vectors.

# Supported Algorithms

| Algorithm          | Supported | Algorithm Type | JWK Type |
|--------------------|:---------:|:--------------:|:--------:|
| HS256              |    YES    |   Signature    |    oct   |
| HS384              |    YES    |   Signature    |    oct   |
| HS512              |    YES    |   Signature    |    oct   |
| RS256              |    YES    |   Signature    |    RSA   |
| RS384              |    YES    |   Signature    |    RSA   |
| RS512              |    YES    |   Signature    |    RSA   |
| ES256              |    YES    |   Signature    |     EC   |
| ES384              |    YES    |   Signature    |     EC   |
| ES512              |    YES    |   Signature    |     EC   |
| PS256              |    YES    |   Signature    |    RSA   |
| PS384              |    YES    |   Signature    |    RSA   |
| PS512              |    YES    |   Signature    |    RSA   |
| none               |     NO    |   Signature    |    N/A   |
| RSA1_5             |    YES    |   Key Wrap     |    RSA   |
| RSA-OAEP           |    YES    |   Key Wrap     |    RSA   |
| RSA-OAEP-256       |    YES    |   Key Wrap     |    RSA   |
| A128KW             |    YES    |   Key Wrap     |    oct   |
| A192KW             |    YES    |   Key Wrap     |    oct   |
| A256KW             |    YES    |   Key Wrap     |    oct   |
| dir                |    YES    |   Key Wrap     |    oct   |
| ECDH-ES            |    YES    |   Key Wrap     |     EC   |
| ECDH-ES+A128KW     |    YES    |   Key Wrap     |     EC   |
| ECDH-ES+A192KW     |    YES    |   Key Wrap     |     EC   |
| ECDH-ES+A256KW     |    YES    |   Key Wrap     |     EC   |
| A128GCMKW          |    YES    |   Key Wrap     |    oct   |
| A192GCMKW          |    YES    |   Key Wrap     |    oct   |
| A256GCMKW          |    YES    |   Key Wrap     |    oct   |
| PBES2-HS256+A128KW |    YES    |   Key Wrap     |    N/A   |
| PBES2-HS384+A192KW |    YES    |   Key Wrap     |    N/A   |
| PBES2-HS512+A256KW |    YES    |   Key Wrap     |    N/A   |
| A128CBC-HS256      |    YES    |   Encryption   |    oct   |
| A192CBC-HS384      |    YES    |   Encryption   |    oct   |
| A256CBC-HS512      |    YES    |   Encryption   |    oct   |
| A128GCM            |    YES    |   Encryption   |    oct   |
| A192GCM            |    YES    |   Encryption   |    oct   |
| A256GCM            |    YES    |   Encryption   |    oct   |

# José Command-Line Utility
José provides a command-line utility which encompasses most of the JOSE
features. This allows for easy integration into your project and one-off
scripts. Below you will find examples of the common commands.

### Key Management

José can generate keys, remove private keys and show thumbprints. For example:

```sh
# Generate three different kinds of keys
$ jose gen -t '{"alg": "A128GCM"}' -o oct.jwk
$ jose gen -t '{"alg": "RSA1_5"}' -o rsa.jwk
$ jose gen -t '{"alg": "ES256"}' -o ec.jwk

# Remove the private keys
$ jose pub -i oct.jwk -o oct.pub.jwk
$ jose pub -i rsa.jwk -o rsa.pub.jwk
$ jose pub -i ec.jwk -o ec.pub.jwk

# Calculate thumbprints
$ jose thp -i oct.jwk
9ipMcxQLsI56Mqr3yYS8hJguJ6Mc8Zh6fkufoiKokrM
$ jose thp -i rsa.jwk
rS6Yno3oQYRIztC6np62nthbmdydhrWmK2Zn_Izmerw
$ jose thp -i ec.jwk
To8yMD92X82zvGoERAcDzlPP6awMYGM2HYDc1G5xOtc
```

### Signatures
José can sign and verify data. For example:

```sh
$ echo hi | jose sig -i- -k ec.jwk -o msg.jws
$ jose ver -i msg.jws -k ec.pub.jwk
hi
$ jose ver -i msg.jws -k oct.jwk
No signatures validated!
```

### Encryption
José can encrypt and decrypt data. For example:

```sh
$ echo hi | jose enc -i- -k rsa.pub.jwk -o msg.jwe
$ jose dec -i msg.jwe -k rsa.jwk
hi
$ jose dec -i msg.jwe -k oct.jwk
Decryption failed!
```
