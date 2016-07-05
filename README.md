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
| none               |    YES    |   Signature    |    N/A   |
| RSA1_5             |    YES    |   Key Wrap     |    RSA   |
| RSA-OAEP           |    YES    |   Key Wrap     |    RSA   |
| RSA-OAEP-256       |    YES    |   Key Wrap     |    RSA   |
| A128KW             |    YES    |   Key Wrap     |    oct   |
| A192KW             |    YES    |   Key Wrap     |    oct   |
| A256KW             |    YES    |   Key Wrap     |    oct   |
| dir                |    YES    |   Key Wrap     |    oct   |
| ECDH-ES            |     NO    |   Key Wrap     |     EC   |
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

### Generating Keys

The simplest way to create a new key is to specify the algorithm that will be
used with the key. For example:
```sh
$ echo '{"alg": "A128GCM"}' | jose gen
{ "kty": "oct", "k": "...", "alg": "A128GCM",
  "use": "enc", "key_ops": ["encrypt", "decrypt"] }

$ jose gen -t '{"alg": "RSA1_5"}'
{ "kty": "RSA", "alg": "RSA1_5", "use": "enc",
  "key_ops": ["wrapKey", "unwrapKey"], ... }
```

Note that when specifying an algorithm, default parameters such as "use" and
"key_ops" will be created if not specified.

Alternatively, key parameters can be specified directly:
```sh
$ jose gen -t '{ "kty": "EC", "crv": "P-256" }'
{ "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "d": "..." }

$ jose gen -t '{"kty": "oct", "bytes": 32}'
{ "kty": "oct", "k": "..." }

$ jose gen -t '{"kty": "RSA", "bits": 4096}'
{ "kty": "RSA", "n": "...", "e": "...", ... }
```

### Protecting Private Keys

There is oftentimes a need to distribute a key file without the enclosed
private keys. José provides an easy way to do this. This command simply takes
a JWK as input and outputs a JWK:

```sh
$ jose pub -i ec.jwk
{ "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }

$ cat ec.jwk | jose pub
{ "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
```

### Signing a Payload
This command signs some input data using one or more JWKs and produces a JWS.

When creating multiple signatures, JWS general format is used:
```sh
$ echo hi | jose sig ec.jwk rsa.jwk
{ "payload": "aGkK", "signatures": [
  { "protected": "...", "signature": "..." },
  { "protected": "...", "signature": "..." } ] }
```

With a single signature, JWS flattened format is used:
```sh
$ echo hi | jose sig ec.jwk
{ "payload": "aGkK", "protected": "...", "signature": "..." }
```

Alternatively, JWS compact format may be used:
```sh
$ echo hi | jose sig -c ec.jwk
eyJhbGciOiJFUzI1NiJ9.aGkK.VauBzVLMesMtTtGfwVOHh9WN1dn6iuEkmebFpJJu...
```

If the payload is specified in the template, stdin is not used:
```sh
$ jose sig -t '{ "payload": "aGkK" }' rsa.jwk
{ "payload": "aGkK", "protected": "...", "signature": "..." }
```

The same is true when using an input file:
```sh
$ jose sig -i message.txt rsa.jwk
{ "payload": "aGkK", "protected": "...", "signature": "..." }
```

### Verifying a Signature

Here are some examples. First, we create a signature with two keys:
```sh
$ echo hi | jose sig -o /tmp/greeting.jws rsa.jwk ec.jwk
```

We can verify this signature with either key using an input file or stdin:
```sh
$ jose ver -i /tmp/greeting.jws ec.jwk
hi
$ cat /tmp/greeting.jws | jose ver rsa.jwk
hi
```

When we use a different key, validation fails:
```sh
$ jose ver -i /tmp/greeting.jws oct.jwk
No signatures validated!
```

Normally, we want validation to succeed if any key validates:
```sh
$ jose ver -i /tmp/greeting.jws rsa.jwk oct.jwk
hi
```

However, we can also require validation of all specified keys:
```sh
$ jose ver -a -i /tmp/greeting.jws rsa.jwk oct.jwk
Signature validation failed!
```

### Encrypting Plaintext
When encrypting to multiple recipients, JWE general format is used:
```sh
$ echo hi | jose enc rsa.jwk oct.jwk
{ "ciphertext": "...", "recipients": [{...}, {...}], ...}
```

With a single recipient, JWE flattened format is used:
```sh
$ echo hi | jose enc rsa.jwk
{ "ciphertext": "...", "encrypted_key": "...", ... }
```

Alternatively, if you ensure that no shared or unprotected headers would be
generated, JWE compact format may be used:
```sh
$ echo hi | jose enc -c -t '{"protected":{"alg":"RSA1_5"}}' rsa.jwk
eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.ZBRtX0Z0vaCMMg...
```

By tweaking the JWE template, you can choose alternate crypto parameters:
```sh
$ echo hi | jose enc -t '{"unprotected":{"enc":"A128GCM"}}' rsa.jwk
{ "ciphertext": "...", "unprotected": { "enc": "A128GCM" }, ... }
```

Transparent plaintext compression is also supported:
```sh
$ echo hi | jose enc -t '{"protected":{"zip":"DEF"}}' rsa.jwk
{ "ciphertext": "...", ... }
```

You can encrypt to one or more passwords by using the '-p' option. This can
even be mixed with JWKs:
```sh
$ echo hi | jose enc -p
Please enter a password:
Please re-enter the previous password:
{ "ciphertext": "...", ... }

$ echo hi | jose enc -p rsa.jwk -p oct.jwk
Please enter a password:
Please re-enter the previous password:
Please enter a password:
Please re-enter the previous password:
{ "ciphertext": "...", ... }
```

### Decrypting Ciphertext
Here are some examples. First, we encrypt a message with three keys:
```sh
$ echo hi | jose enc -o /tmp/greeting.jws -p rsa.jwk oct.jwk
Please enter a password:
Please re-enter the previous password:
```

We can decrypt this message with any JWK using an input file or stdin:
```sh
$ jose dec -i /tmp/greeting.jws oct.jwk
hi
$ cat /tmp/greeting.jws | jose dec rsa.jwk
hi
```

We can also decrypt this message using the password:
```sh
$ jose dec -i /tmp/greeting.jws
Please enter password:
hi
```

When we use a different key and suppress prompting, decryption fails:
```sh
$ jose dec -n -i /tmp/greeting.jws ec.jwk
Decryption failed!
```
