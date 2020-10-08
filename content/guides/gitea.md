# Adding a Gitea proof

Let's add a decentralized Gitea proof to your OpenPGP keys. This will also work on self-hosted instances.

[[toc]]

## Post a Gitea proof message

Log in to a gitea instance like [codeberg.org](https://codeberg.org) and click on **Create new repository**.

Set the repository name to **gitea_proof**.

Set the project description to (make sure to replace FINGERPRINT):

```
[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

Optional: edit the README.md to this:

```
This is an OpenPGP proof that connects my OpenPGP key to this Gitea account. For details check out https://keyoxide.org/guides/openpgp-proofs
```

After creating the project, copy the link to the project.

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to update with the link to the project copied above):

`proof@metacode.biz=https://gitea.example.com/USERNAME/gitea_proof`

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Gitea account.
