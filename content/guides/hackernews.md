# Adding a Hackernews proof

Let's add a decentralized Hackernews proof to your OpenPGP keys.

[[toc]]

## Update the Hackernews account

Log in to [Hackernews](https://news.ycombinator.com) and click on your **username**.

Add the following lines to your **about** (make sure to replace FINGERPRINT):

```
This is an OpenPGP proof that connects my OpenPGP key to this Hackernews account. For details check out https://keyoxide.org/guides/openpgp-proofs

[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to replace USERNAME):

`proof@metacode.biz=https://news.ycombinator.com/user?id=USERNAME`

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Hackernews account.
