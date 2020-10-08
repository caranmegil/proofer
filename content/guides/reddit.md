# Adding a Reddit proof

Let's add a decentralized Reddit proof to your OpenPGP keys.

[[toc]]

## Post a Reddit proof message

Log in to [www.reddit.com](https://www.reddit.com) and create a new post with the following text (make sure to replace FINGERPRINT):

```
This is an OpenPGP proof that connects my OpenPGP key to this Reddit account. For details check out https://keyoxide.org/guides/openpgp-proofs

[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

After posting, copy the link to the post.

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to update with the link to the post copied above):

`proof@metacode.biz=https://www.reddit.com/user/USERNAME/comments/123123/TITLE/`

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Reddit account.
