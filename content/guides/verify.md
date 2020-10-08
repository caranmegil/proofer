# Verifying a signature

Let's see how to verify an OpenPGP signature.

[[toc]]

## Obtain a signature

If you already have a signature you would like to verify, great! If not, let's use the following signature for the guide:

```
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

I like pineapple.
-----BEGIN PGP SIGNATURE-----

iQJDBAEBCAAtFiEEog/Pt4tEmnyVrrtlNzZ/SvQIetEFAl70mVUPHHlhcm1vQHlh
cm1vLmV1AAoJEDc2f0r0CHrRQXIP/08uza9zOtmZXv5K+uPGVzDKwkgPgZJEezX7
6iQ358f1pjSRvYfQ5aB13k2epUHoqCKArMYu1zPqxhvLvvAvp8uOHABnr9NGL3El
u7UUgaeUNHkr0gxCKEq3p81abrrbbWveP8OBP4RyxmaFx13Xcj7mfDluiBHmjVvv
WU09EdH9VPlJ7WfZ+2G2ZZDHuE5XiaeP7ocugTxXXLkp33zwpDX0+ZuCIXM6fQGe
OccSffglFPdNBnfasuuxDWxTQPsEbWGOPJV+CAPmBDeApX+TBF9bovO3hw4Uozk2
VT7EAy8Hb0SOrUb3UNGxzoKv++5676IxyB4JXX0Tr9O4ZxhO8o9pEEHwirtn/J1+
MWven4gVlWM/6bMeUqx6ydyNc2nqF5059yfRmwGMlp09x82G4x1bcf6aDZ+5njDG
fS5T2OpXRIkZHJx8BhmZjsxiDR0KV44zwHpt06+96ef3EDWB0BcP6M+a5Rtc33zf
irRmQd2M6RLyXCYtdGIiiAFRuomw802U4F0P4LwVrZdbGA6ObqBv1k8BUFCMbMz8
Ab4hF7kO4z0Vh3JaKzcHey0pOzdNCPpAHZ51sAoAnFDM4PdMBgQxxVweCMu4KYMZ
FN8sNn42oY/b7gDmwCelVhgD+rvUn/a8+B7CDmCp+wIquyrjrTt00voATcb+ZPMJ
pTXJ/NcM
=rqTX
-----END PGP SIGNATURE-----
```

Copy the above signature.

## Verify the signature

Open the [/verify](/verify) page and paste the signature in the corresponding field. Scroll down and press the **VERIFY SIGNATURE** button.

Keyoxide lets you know the signature was verified and signed by a certain person.

## Verify the signature against a specific public key

Sometimes, you want to know if a specific person or public key was used to create a signature. In this case, let's figure out if the message was signed by Yarmo's public key or his friend Wiktor's public key.

Copy the following fingerprint:

`653909A2F0E37C106F5FAF546C8857E0D8E8F074`

Paste it in the **Email / key id / fingerprint** field under **Public Key (3: HKP server)** and press the big button again. It could not be verified. Guess it wasn't Wiktor who signed that message.

Now, copy the following fingerprint:

`9f0048ac0b23301e1f77e994909f6bd6f80f485d`

Paste it in the same field and press the big button again. It did verify! It was Yarmo all along.

## Going further

You could try using different mechanisms of fetching keys, such as **web key directory** or copy-pasting a plaintext public key.

If you'd like to sign messages using PGP, you must first learn the fundamentals of PGP and how to generate and handle your own keypair.
