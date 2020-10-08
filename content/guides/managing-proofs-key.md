# Listing Proofs using GnuPG

Let's list the identity proofs stored in our OpenPGP keys.

## Listing notations in GnuPG

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

List detailed preferences:

`showpref`

You should now see your key details, uid, and proofs assigned to your keys:

```
[ultimate] (1). Your Name <your@email>
  Cipher: AES256, AES192, AES, 3DES
  Digest: SHA512, SHA384, SHA256, SHA1
  Compression: ZLIB, BZIP2, ZIP, Uncompressed
  Features: MDC, Keyserver no-modify
  Notations: proof@metacode.biz=https://gist.github.com/youruser/somehash
             proof@metacode.biz=dns:yourdomain.org?type=TXT</your@email>
```

Exit gpg:

`quit`
