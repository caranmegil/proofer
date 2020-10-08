# Adding a Mastodon proof

Let's add a decentralized Mastodon proof to your OpenPGP keys.

[[toc]]

## Update the Mastodon account

Log in to your Mastodon instance and click on **Edit profile**.

Add a new item under **Profile metadata** with the label **OpenPGP** and your PGP fingerprint as the content, or with the label **Keyoxide** and your Keyoxide profile URL as the content.

## Update the PGP key

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to update the link):

`proof@metacode.biz=https://INSTANCE.ORG/@USERNAME`

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a verified Mastodon account.
