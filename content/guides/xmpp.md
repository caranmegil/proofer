# Adding a XMPP proof

Let's add a decentralized XMPP proof to your OpenPGP keys.

[[toc]]

### Add a message to your XMPP vCard

Using a XMPP client that supports editing the vCard (such as [Dino](https://dino.im/) and [Gajim](https://gajim.org/)), append the following message to the **About** section (make sure to replace FINGERPRINT):

```
This is an OpenPGP proof that connects my OpenPGP key to this XMPP account. For details check out https://keyoxide.org/guides/openpgp-proofs

[Verifying my OpenPGP key: openpgp4fpr:FINGERPRINT]
```

### Update the PGP key (basic edition)

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Add a new notation:

`notation`

Enter the notation (make sure to replace XMPP-ID):

`proof@metacode.biz=xmpp:XMPP-ID`

The XMPP-ID looks something like an email address: **user@domain.org**.

Save the key:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`

And you're done! Reload your profile page, it should now show a XMPP account.

### Update the PGP key (OMEMO edition)

XMPP communication can be end-to-end encrypted with [OMEMO](https://conversations.im/omemo/). Verifying OMEMO fingerprints is essential to trust your communication and keep it safe from Man-in-the-Middle attacks.

**Keyoxide** makes the fingerprint verification process easy for all. Add a special identity proof that not only contains your XMPP-ID but also the fingerprints of all your OMEMO keys.

If your XMPP identity proof is verified, a QR code is shown. Anyone can scan this QR code using XMPP apps like [Conversations](https://conversations.im/) (free on [F-Droid](https://f-droid.org/en/packages/eu.siacs.conversations/)) to not only add you as a contact, but also verify your OMEMO keys with the highest level of trust.

Making this identity proof yourself can be a tad difficult when using clients like Gajim, but luckily for us, [Conversations](https://conversations.im/) can directly generate the proof by going to **Account details > Share > Share as XMPP URI**. The resulting URI should look something like:

`xmpp:user@domain.org?omemo-sid-123456789=A1B2C3D4E5F6G7H8I9...`

To take advantage of the easy and secure XMPP identity proof including OMEMO fingerprints, follow the **basic edition** guide above but replace XMPP-ID with the URI obtained through the **Conversations** app.
