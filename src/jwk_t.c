/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */

#include "jwk.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>

struct kv {
    const char *key;
    const char *val;
};

static const struct {
    int type;
    struct kv *base;
    struct kv *prvt;
    struct kv *xtra;
    union {
        const char *oct;
        struct rsa {
            const char *n;
            const char *e;
            const char *d;
            const char *p;
            const char *q;
            const char *dp;
            const char *dq;
            const char *qi;
        } rsa;
        struct ec {
            const char *pub;
            const char *prv;
        } ec;
    } test;
} vectors[] = {
    { EVP_PKEY_EC, /* RFC 7517 - A.1 */
      (struct kv[]) {
          { "kty", "EC" },
          { "crv", "P-256" },
          { "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4" },
          { "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM" },
          {}
      },
      (struct kv[]) {
          {}
      },
      (struct kv[]) {
          { "use", "enc" },
          { "kid", "1" },
          {}
      },
      { .ec = {
        "0330A0424CD21C2944838A2D75C92B37E76EA20D9F00893A3B4EEE8A3C0AAFEC3E"
      } } },
    { EVP_PKEY_RSA, /* RFC 7517 - A.1 */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfA"
                 "AtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhM"
                 "stn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGj"
                 "QR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5"
                 "hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcR"
                 "wr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          {}
      },
      (struct kv[]) {
          { "alg", "RS256" },
          { "kid", "2011-04-29" },
          {}
      },
      { .rsa = {
          "D2FC7B6A0A1E6C67104AEB8F88B257669B4DF679DDAD099B5C4A6CD9A88015B5"
          "A133BF0B856C7871B6DF000B554FCEB3C2ED512BB68F145C6E8434752FAB52A1"
          "CFC124408F79B58A4578C16428855789F7A249E384CB2D9FAE2D67FD96FB926C"
          "198E077399FDC815C0AF097DDE5AADEFF44DE70E827F4878432439BFEEB96068"
          "D0474FC50D6D90BF3A98DFAF1040C89C02D692AB3B3C2896609D86FD73B774CE"
          "0740647CEEEAA310BD12F985A8EB9F59FDD426CEA5B2120F4F2A34BCAB764B7E"
          "6C54D6840238BCC40587A59E66ED1F33894577635C470AF75CF92C20D1DA43E1"
          "BFC419E222A6F0D0BB358C5E38F9CB050AEAFE904814F1AC1AA49CCA9EA0CA83",
          "010001"
      } } },
    { EVP_PKEY_EC, /* RFC 7517 - A.2 */
      (struct kv[]) {
          { "kty", "EC" },
          { "crv", "P-256" },
          { "x", "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4" },
          { "y", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM" },
          {}
      },
      (struct kv[]) {
          { "d", "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE" },
          {}
      },
      (struct kv[]) {
          { "use", "enc" },
          { "kid", "1" },
          {}
      },
      { .ec = {
        "0330A0424CD21C2944838A2D75C92B37E76EA20D9F00893A3B4EEE8A3C0AAFEC3E",
        "F3BD0C07A81FB932781ED52752F60CC89A6BE5E51934FE01938DDB55D8F77801"
      } } },
    { EVP_PKEY_RSA, /* RFC 7517 - A.2 */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfA"
                 "AtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhM"
                 "stn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGj"
                 "QR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5"
                 "hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2Ncr"
                 "wr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          { "d", "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5"
                 "oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfq"
                 "ijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYa"
                 "MwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu"
                 "4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4"
                 "j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q" },
          { "p", "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD"
                 "20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIY"
                 "QyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs" },
          { "q", "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjV"
                 "ZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78T"
                 "zFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk" },
          { "dp","G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxI"
                 "i2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_N"
                 "mtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0" },
          { "dq","s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfB"
                 "cMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb"
                 "_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk" },
          { "qi","GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZE"
                 "VFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ1"
                 "1rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU" },
          {}
      },
      (struct kv[]) {
          { "alg", "RS256" },
          { "kid", "2011-04-29" },
          {}
      },
      { .rsa = {
          "D2FC7B6A0A1E6C67104AEB8F88B257669B4DF679DDAD099B5C4A6CD9A88015B5"
          "A133BF0B856C7871B6DF000B554FCEB3C2ED512BB68F145C6E8434752FAB52A1"
          "CFC124408F79B58A4578C16428855789F7A249E384CB2D9FAE2D67FD96FB926C"
          "198E077399FDC815C0AF097DDE5AADEFF44DE70E827F4878432439BFEEB96068"
          "D0474FC50D6D90BF3A98DFAF1040C89C02D692AB3B3C2896609D86FD73B774CE"
          "0740647CEEEAA310BD12F985A8EB9F59FDD426CEA5B2120F4F2A34BCAB764B7E"
          "6C54D6840238BCC40587A59E66ED1F33894577635CAF0AF75CF92C20D1DA43E1"
          "BFC419E222A6F0D0BB358C5E38F9CB050AEAFE904814F1AC1AA49CCA9EA0CA83",
          "010001",
          "5F8713B5E258FE09F81583EC5C1F2B7578B1E6FC2C83514B37913711A1BA449A"
          "151FE1CB2CA0FD33B771E68A3B1944649DC867AD1C1E5240BB853E5F24B33459"
          "B14028D2D6636BEFEC1E8DA974B352FC53D3F6127EA8A3C29DD14F3941682C56"
          "A78768164E4DDA8F06CBF9C734AAE8003224278EA9454A21B17CB06D17807586"
          "8CC05B3DB6FF1DFDC3D56378B4EDADEDF0C37A4CDC26D1D49AC26F6FE3B5220A"
          "5DD29396621BBC688CF2EEE2C6E0D54DA3C782014CD0739DB252CC51CAEBA8D3"
          "F1B824BAAB24D068EC903264D7D678AB08F06EC9E7E23D960628B744BF94B369"
          "4656463C7E417399ED73D076C891FCF463A9AA9CE62DA9CD17E237DC2A8002F1",
          "F378BEEC8BCC197A0C5C2B24BFBDD32ABF3ADFB1623BB676EF3BFCA23EA96D65"
          "10C8B3D0050C6D3D59F00F6D11FBAD1E4C3983DAE8E732DE4FA2A32B9BC45F98"
          "D855583B638CC9823233A949789C1478FB5CEB95218432A955A558487A74DDFA"
          "19565893DDCDF0173DBD8E35C72F01F51CF3386550CD7BCD12F9FB3B49D56DFB",
          "DDD7CE47D72E62AFB44BE9A414BCE022D80C11F173076AB78567A132E1B4A02B"
          "AA9DBDEFA1B2F2BA6AA355940ED5D22B7708139C276963305C39F5B9AF7EF400"
          "55E38967EDFCD1848A8BE89E2CE12A9A3D5554BBF13CC583190876B79C45ECEC"
          "67ED6461DFECD6A0DBC6D9031207C0213006F4B527003BA7E2F21C6FAC9E9719",
          "1B8B0F5E473A61AF72F28256F7F20B8F8C6EA69BB49738BF1FB553912F318F94"
          "9D5F7728134A22998C31222D9E99302E7B450E6B97698051B2049E1CF2D43654"
          "5E34D9746E80A0D33FC6A4621168E6D000EFB41EFCD9ADB9865CDC2DE6DC8DB8"
          "1B61AF479B120F153200DDB3ABC2DF9FD1149ACEAB63739BF187A22A44E2063D",
          "B3D9401FD7E0801B28151F0E69CD91FC4DA0C36F36AD3DA418E021BC89651131"
          "3579FAC0EA1B9452F31F05C3299FC96A796EAFCF39D8639492405EE931D0BF6A"
          "02379C6F086E9D4151BD09522ADA44DA947CB85C41BFDDF461780E1EDEEF859B"
          "46CA1B4689EE8D360DD7109A3FA4CEEB58EF5AB5FE2F5F2DC57C38F7843F7209",
          "1B233FA7A26B5F24A2CF5B6816029B595F89748DE3438CA9BBDADB316C77AD02"
          "417E6B7416863381421911514470EAB07A644DF35CE80C069AF819342963460E"
          "3247643743985856DC037B948FA9BB193F987646275D6BC7247C3B9E572D27B7"
          "48F9917CAC1923AC94DB8671BD0285608B5D95D50A1B33BA21AEB34CA8405515",
      } } },
    { EVP_PKEY_HMAC, /* RFC 7517 - A.3 */
      (struct kv[]) {
          { "kty", "oct" },
          {}
      },
      (struct kv[]) {
          { "k", "GawgguFyGrWKav7AX4VKUg" },
          {}
      },
      (struct kv[]) {
          { "alg", "A128KW" },
          {}
      },
      { .oct = "19AC2082E1721AB58A6AFEC05F854A52" } },
    { EVP_PKEY_HMAC, /* RFC 7517 - A.3 */
      (struct kv[]) {
          { "kty", "oct" },
          {}
      },
      (struct kv[]) {
          { "k", "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_"
                 "T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow" },
          {}
      },
      (struct kv[]) {
          { "kid", "HMAC key used in JWS spec Appendix A.1 example" },
          {}
      },
      { .oct = "0323354B2B0FA5BC837E0665777BA68F5AB328E6F054C928A90F84B2D25"
               "02EBFD3FB5A92D20647EF968AB4C377623D223D2E2172052E4F08C0CD9A"
               "F567D080A3" } },
    { EVP_PKEY_RSA, /* RFC 7517 - B (x5c parameter omitted) */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PL"
                 "bK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0"
                 "Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxT"
                 "Wq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wg"
                 "zjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPd"
                 "wS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          {}
      },
      (struct kv[]) {
          { "use", "sig" },
          { "kid", "1b94c" },
          {}
      },
      { .rsa = {
          "BEB8CE7F3F4271D831E6742E77285DA11D7B57E22E6D631E3990B05FF8E3D218"
          "00B33D89FE9A985B4F0F2DB2BF3DD89518A3EBAB398322C2C8EEC036E551271D"
          "4D6E08B37006E52208ED75FFEEDD61BB2BE222661B442EDA3F03B15C93D5ACE9"
          "242FCD1BCE13CB928AB61B8268FA1DEE223BC342CAF68AD2321044C306430B14"
          "D6AB869858072173CB7E7A677DA8EBD6B553030B605792C467821E97E5B5182F"
          "2E80C872AF8FE9D4CB5C20CE36100F01CC4E9942A0BB54FA8FBC48D9D9D6D991"
          "A0613DB899012DD87980510D69B5A75399B566A64F7704BEAA8FA678CBD57C96"
          "FA8C9556469976494B429D81B60B7DAABDB59B8D9FE304F0F97AE9EAB08A35BD",
          "010001",
      } } },
    { EVP_PKEY_RSA, /* RFC 7517 - C.1 */
      (struct kv[]) {
          { "kty", "RSA" },
          { "n", "t6Q8PWSi1dkJj9hTP8hNYFlvadM7DflW9mWepOJhJ66w7nyoK1gPNqFMS"
                 "QRyO125Gp-TEkodhWr0iujjHVx7BcV0llS4w5ACGgPrcAd6ZcSR0-Iqom"
                 "-QFcNP8Sjg086MwoqQU_LYywlAGZ21WSdS_PERyGFiNnj3QQlO8Yns5jC"
                 "tLCRwLHL0Pb1fEv45AuRIuUfVcPySBWYnDyGxvjYGDSM-AqWS9zIQ2Zil"
                 "gT-GqUmipg0XOC0Cc20rgLe2ymLHjpHciCKVAbY5-L32-lSeZO-Os6U15"
                 "_aXrk9Gw8cPUaX1_I8sLGuSiVdt3C_Fn2PZ3Z8i744FPFGGcG1qs2Wz-Q" },
          { "e", "AQAB" },
          {}
      },
      (struct kv[]) {
          { "d", "GRtbIQmhOZtyszfgKdg4u_N-R_mZGU_9k7JQ_jn1DnfTuMdSNprTeaSTy"
                 "WfSNkuaAwnOEbIQVy1IQbWVV25NY3ybc_IhUJtfri7bAXYEReWaCl3hdl"
                 "PKXy9UvqPYGR0kIXTQRqns-dVJ7jahlI7LyckrpTmrM8dWBo4_PMaenNn"
                 "PiQgO0xnuToxutRZJfJvG4Ox4ka3GORQd9CsCZ2vsUDmsXOfUENOyMqAD"
                 "C6p1M3h33tsurY15k9qMSpG9OX_IJAXmxzAh_tWiZOwk2K4yxH9tS3Lq1"
                 "yX8C1EWmeRDkK2ahecG85-oLKQt5VEpWHKmjOi_gJSdSgqcN96X52esAQ" },
          { "p", "2rnSOV4hKSN8sS4CgcQHFbs08XboFDqKum3sc4h3GRxrTmQdl1ZK9uw-P"
                 "IHfQP0FkxXVrx-WE-ZEbrqivH_2iCLUS7wAl6XvARt1KkIaUxPPSYB9yk"
                 "31s0Q8UK96E3_OrADAYtAJs-M3JxCLfNgqh56HDnETTQhH3rCT5T3yJws" },
          { "q", "1u_RiFDP7LBYh3N4GXLT9OpSKYP0uQZyiaZwBtOCBNJgQxaj10RWjsZu0"
                 "c6Iedis4S7B_coSKB0Kj9PaPaBzg-IySRvvcQuPamQu66riMhjVtG6TlV"
                 "8CLCYKrYl52ziqK0E_ym2QnkwsUX7eYTB7LbAHRK9GqocDE5B0f808I4s" },
          { "dp","KkMTWqBUefVwZ2_Dbj1pPQqyHSHjj90L5x_MOzqYAJMcLMZtbUtwKqvVD"
                 "q3tbEo3ZIcohbDtt6SbfmWzggabpQxNxuBpoOOf_a_HgMXK_lhqigI4y_"
                 "kqS1wY52IwjUn5rgRrJ-yYo1h41KR-vz2pYhEAeYrhttWtxVqLCRViD6c" },
          { "dq","AvfS0-gRxvn0bwJoMSnFxYcK1WnuEjQFluMGfwGitQBWtfZ1Er7t1xDkb"
                 "N9GQTB9yqpDoYaN06H7CFtrkxhJIBQaj6nkF5KKS3TQtQ5qCzkOkmxIe3"
                 "KRbBymXxkb5qwUpX5ELD5xFc6FeiafWYY63TmmEAu_lRFCOJ3xDea-ots" },
          { "qi","lSQi-w9CpyUReMErP1RsBLk7wNtOvs5EQpPqmuMvqW57NBUczScEoPwmU"
                 "qqabu9V0-Py4dQ57_bapoKRu1R90bvuFnU63SHWEFglZQvJDMeAvmj4sm"
                 "-Fp0oYu_neotgQ0hzbI5gry7ajdYy9-2lNx_76aBZoOUu9HCJ-UsfSOI8" },
          {}
      },
      (struct kv[]) {
          { "kid", "juliet@capulet.lit" },
          { "use", "enc" },
          {}
      },
      { .rsa = {
          "B7A43C3D64A2D5D9098FD8533FC84D60596F69D33B0DF956F6659EA4E26127AE"
          "B0EE7CA82B580F36A14C4904723B5DB91A9F93124A1D856AF48AE8E31D5C7B05"
          "C5749654B8C390021A03EB70077A65C491D3E22AA26F9015C34FF128E0D3CE8C"
          "C28A9053F2D8CB0940199DB5592752FCF111C861623678F741094EF189ECE630"
          "AD2C24702C72F43DBD5F12FE3902E448B947D570FC920566270F21B1BE36060D"
          "233E02A592F73210D998A5813F86A949A2A60D17382D02736D2B80B7B6CA62C7"
          "8E91DC88229501B639F8BDF6FA549E64EF8EB3A535E7F697AE4F46C3C70F51A5"
          "F5FC8F2C2C6B9289576DDC2FC59F63D9DD9F22EF8E053C5186706D6AB365B3F9",
          "010001",
          "191B5B2109A1399B72B337E029D838BBF37E47F999194FFD93B250FE39F50E77"
          "D3B8C752369AD379A493C967D2364B9A0309CE11B210572D4841B595576E4D63"
          "7C9B73F221509B5FAE2EDB01760445E59A0A5DE17653CA5F2F54BEA3D8191D24"
          "2174D046A9ECF9D549EE36A1948ECBC9C92BA539AB33C756068E3F3CC69E9CD9"
          "CF89080ED319EE4E8C6EB516497C9BC6E0EC7891ADC639141DF42B02676BEC50"
          "39AC5CE7D410D3B232A0030BAA75337877DEDB2EAD8D7993DA8C4A91BD397FC8"
          "2405E6C73021FED5A264EC24D8AE32C47F6D4B72EAD725FC0B511699E44390AD"
          "9A85E706F39FA82CA42DE551295872A68CE8BF80949D4A0A9C37DE97E767AC01",
          "DAB9D2395E2129237CB12E0281C40715BB34F176E8143A8ABA6DEC738877191C"
          "6B4E641D97564AF6EC3E3C81DF40FD059315D5AF1F9613E6446EBAA2BC7FF688"
          "22D44BBC0097A5EF011B752A421A5313CF49807DCA4DF5B3443C50AF7A137FCE"
          "AC00C062D009B3E33727108B7CD82A879E870E71134D0847DEB093E53DF2270B",
          "D6EFD18850CFECB0588773781972D3F4EA522983F4B9067289A67006D38204D2"
          "604316A3D744568EC66ED1CE8879D8ACE12EC1FDCA12281D0A8FD3DA3DA07383"
          "E232491BEF710B8F6A642EEBAAE23218D5B46E93955F022C260AAD8979DB38AA"
          "2B413FCA6D909E4C2C517EDE61307B2DB00744AF46AA87031390747FCD3C238B",
          "2A43135AA05479F570676FC36E3D693D0AB21D21E38FDD0BE71FCC3B3A980093"
          "1C2CC66D6D4B702AABD50EADED6C4A3764872885B0EDB7A49B7E65B382069BA5"
          "0C4DC6E069A0E39FFDAFC780C5CAFE586A8A0238CBF92A4B5C18E762308D49F9"
          "AE046B27EC98A35878D4A47EBF3DA9621100798AE1B6D5ADC55A8B0915620FA7",
          "02F7D2D3E811C6F9F46F02683129C5C5870AD569EE12340596E3067F01A2B500"
          "56B5F67512BEEDD710E46CDF4641307DCAAA43A1868DD3A1FB085B6B93184920"
          "141A8FA9E417928A4B74D0B50E6A0B390E926C487B72916C1CA65F191BE6AC14"
          "A57E442C3E7115CE857A269F59863ADD39A6100BBF951142389DF10DE6BEA2DB",
          "952422FB0F42A7251178C12B3F546C04B93BC0DB4EBECE444293EA9AE32FA96E"
          "7B34151CCD2704A0FC2652AA9A6EEF55D3E3F2E1D439EFF6DAA68291BB547DD1"
          "BBEE16753ADD21D6105825650BC90CC780BE68F8B26F85A74A18BBF9DEA2D810"
          "D21CDB23982BCBB6A3758CBDFB694DC7FEFA681668394BBD1C227E52C7D2388F"
      } } },
    {}
};

static void
test_oct(const ASN1_OCTET_STRING *os, const char *hex)
{
    char tmp[os->length * 2 + 1];

    for (int i = 0; i < os->length; i++)
        sprintf(&tmp[i * 2], "%02X", os->data[i]);

    fprintf(stderr, "%s\n", hex);
    fprintf(stderr, "%s\n", tmp);

    assert(strlen(hex) == strlen(tmp));
    assert(strcmp(hex, tmp) == 0);
}

static void
test_rsa(const RSA *key, const struct rsa *rsa)
{
    struct {
        BIGNUM *num;
        const char *val;
    } nv[] = {
        { key->n, rsa->n },
        { key->e, rsa->e },
        { key->p, rsa->p },
        { key->q, rsa->q },
        { key->d, rsa->d },
        { key->dmp1, rsa->dp },
        { key->dmq1, rsa->dq },
        { key->iqmp, rsa->qi },
        {}
    };

    for (size_t i = 0; nv[i].num; i++) {
        char *tmp = NULL;

        assert(!!nv[i].num == !!nv[i].val);
        if (!nv[i].num)
            continue;

        tmp = BN_bn2hex(nv[i].num);
        assert(tmp);

        fprintf(stderr, "%s\n", nv[i].val);
        fprintf(stderr, "%s\n", tmp);

        assert(strlen(tmp) == strlen(nv[i].val));
        assert(strcmp(tmp, nv[i].val) == 0);
        free(tmp);
    }
}

static void
test_ec(const EC_KEY *key, const struct ec *ec)
{
    char *tmp = NULL;

    tmp = EC_POINT_point2hex(
        EC_KEY_get0_group(key),
        EC_KEY_get0_public_key(key),
        POINT_CONVERSION_COMPRESSED,
        NULL
    );
    assert(tmp);

    fprintf(stderr, "%s\n", ec->pub);
    fprintf(stderr, "%s\n", tmp);

    assert(strlen(tmp) == strlen(ec->pub));
    assert(strcmp(tmp, ec->pub) == 0);
    free(tmp);

    if (!EC_KEY_get0_private_key(key))
        return;

    tmp = BN_bn2hex(EC_KEY_get0_private_key(key));
    assert(tmp);

    fprintf(stderr, "%s\n", ec->prv);
    fprintf(stderr, "%s\n", tmp);

    assert(strlen(tmp) == strlen(ec->prv));
    assert(strcmp(tmp, ec->prv) == 0);
    free(tmp);
}

int
main(int argc, char *argv[])
{
    for (size_t i = 0; vectors[i].base; i++) {
        EVP_PKEY *pkey = NULL;
        json_t *kbase = NULL;
        json_t *kprvt = NULL;
        json_t *kxtra = NULL;
        json_t *cbase = NULL;
        json_t *cprvt = NULL;
        json_t *prvt = NULL;

        kbase = json_object();
        kprvt = json_object();
        kxtra = json_object();
        assert(kbase);
        assert(kprvt);
        assert(kxtra);

        for (size_t j = 0; vectors[i].base[j].key; j++) {
            const char *k = vectors[i].base[j].key;
            const char *v = vectors[i].base[j].val;
            assert(json_object_set_new(kbase, k, json_string(v)) != -1);
            assert(json_object_set_new(kprvt, k, json_string(v)) != -1);
            assert(json_object_set_new(kxtra, k, json_string(v)) != -1);
        }

        for (size_t j = 0; vectors[i].prvt[j].key; j++) {
            const char *k = vectors[i].prvt[j].key;
            const char *v = vectors[i].prvt[j].val;
            assert(json_object_set_new(kprvt, k, json_string(v)) != -1);
            assert(json_object_set_new(kxtra, k, json_string(v)) != -1);
        }

        for (size_t j = 0; vectors[i].xtra[j].key; j++) {
            const char *k = vectors[i].xtra[j].key;
            const char *v = vectors[i].xtra[j].val;
            assert(json_object_set_new(kxtra, k, json_string(v)) != -1);
        }

        fprintf(stderr, "=================================================\n");

        pkey = jose_jwk_to_key(kxtra);
        assert(pkey);

        switch (vectors[i].type) {
        case EVP_PKEY_HMAC:
            test_oct((void *) pkey->pkey.ptr, vectors[i].test.oct);
            break;

        case EVP_PKEY_RSA:
            test_rsa(pkey->pkey.rsa, &vectors[i].test.rsa);
            break;

        case EVP_PKEY_EC:
            test_ec(pkey->pkey.ec, &vectors[i].test.ec);
            break;

        default:
            goto next;
        }

        prvt = jose_jwk_from_key(pkey);
        assert(prvt);

        cprvt = jose_jwk_copy(prvt, true);
        cbase = jose_jwk_copy(prvt, false);
        assert(cprvt);
        assert(cbase);

        assert(!json_equal(prvt, kxtra));
        assert(json_equal(prvt, kprvt));
        assert(json_equal(prvt, kbase) == !vectors[i].prvt[0].key);

        assert(!json_equal(cprvt, kxtra));
        assert(json_equal(cprvt, kprvt));
        assert(json_equal(cprvt, kbase) == !vectors[i].prvt[0].key);

        assert(!json_equal(cbase, kxtra));
        assert(!json_equal(cbase, kprvt) == !!vectors[i].prvt[0].key);
        assert(json_equal(cbase, kbase));

        json_decref(prvt);
        json_decref(cprvt);
        json_decref(cbase);

next:
        EVP_PKEY_free(pkey);
        json_decref(kbase);
        json_decref(kprvt);
        json_decref(kxtra);
    }

    return 0;
}
