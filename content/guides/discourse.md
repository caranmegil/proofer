# Adding a Discourse proof

Let's add a decentralized Discourse proof to your OpenPGP keys.

[[toc]]

## Update the Discourse account

Log in to the discourse instance website and add the following text to your **About me** (make sure to replace FINGERPRINT):

```
This is an OpenPGP proof that connects my OpenPGP key to this Discourse account. For details check out https://keyoxide.org/guides/openpgp-proofs

[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

After posting, copy the link to your profile page (it should end with your **/u/USERNAME**).

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to replace PROFILE_URL with the link to the profile copied above):

`proof@metacode.biz=PROFILE_URL`

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Discourse account.
