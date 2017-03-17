José Command-Line Utility
=========================

José provides a command-line utility which encompasses most of the JOSE
features. This allows for easy integration into your project and one-off
scripts. Below you will find examples of the common commands.

Key Management
~~~~~~~~~~~~~~

José can generate keys, remove private keys and show thumbprints. For
example:

.. code:: sh

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

Signatures
~~~~~~~~~~

José can sign and verify data. For example:

.. code:: sh

    $ echo hi | jose sig -i- -k ec.jwk -o msg.jws
    $ jose ver -i msg.jws -k ec.pub.jwk
    hi
    $ jose ver -i msg.jws -k oct.jwk
    No signatures validated!

Encryption
~~~~~~~~~~

José can encrypt and decrypt data. For example:

.. code:: sh

    $ echo hi | jose enc -i- -k rsa.pub.jwk -o msg.jwe
    $ jose dec -i msg.jwe -k rsa.jwk
    hi
    $ jose dec -i msg.jwe -k oct.jwk
    Decryption failed!
