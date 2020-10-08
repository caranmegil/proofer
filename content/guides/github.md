# Adding a Github proof

Let's add a decentralized Github proof to your OpenPGP keys.

[[toc]]

## Post a Github proof message

Log in to [github.com](https://github.com) and click on **New gist**.

Name the file **openpgp.md** and copy the following content into it (make sure to replace FINGERPRINT and USERNAME):

```
This is an OpenPGP proof that connects [my OpenPGP key](https://keyoxide.org/FINGERPRINT) to [this Github account](https://github.com/USERNAME). For details check out https://keyoxide.org/guides/openpgp-proofs

[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

After creating a public gist, copy the link to the gist.

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to update with the link to the post copied above):

`proof@metacode.biz=https://gist.github.com/USERNAME/12345678912345678912345678912345`

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Github account.
