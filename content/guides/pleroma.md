# Adding a Pleroma proof

Let's add a decentralized Pleroma proof to your OpenPGP keys.

[[toc]]

## Update the Pleroma account

Log in to your Pleroma instance and add the following lines to your **Bio** (make sure to replace FINGERPRINT):

```
This is an OpenPGP proof that connects my OpenPGP key to this Pleroma account. For details check out https://keyoxide.org/guides/openpgp-proofs

[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to update the link):

`proof@metacode.biz=https://INSTANCE.ORG/users/USERNAME`

Please note that the **/users/** part of the URL is mandatory for the proof to work.

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Fediverse account (Pleroma is part of the [Fediverse](#https://en.wikipedia.org/wiki/Fediverse)).
