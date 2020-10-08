# Adding a Twitter proof

Let's add a decentralized Twitter proof to your OpenPGP keys.

[[toc]]

## Post a Twitter proof message

Log in to [twitter.com](https://twitter.com) and compose a new tweet with the following text (make sure to replace FINGERPRINT):

```
This is an OpenPGP proof that connects my OpenPGP key to this Twitter account. For details check out https://keyoxide.org/guides/openpgp-proofs

[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

After posting, copy the link to the tweet.

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to update with the link to the tweet copied above):

`proof@metacode.biz=https://twitter.com/USERNAME/status/1234567891234567891`

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Twitter account.
