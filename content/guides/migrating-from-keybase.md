# Migrating from Keybase

Let's see how easy it is to get a Keyoxide profile when you already have a Keybase account.

[[toc]]

## Claim your Keyoxide profile

Go to the [profile URL generator](/util/profile-url), set Keybase as Source and follow the Keybase specific instructions. Has a profile URL been generated? Congratulations, you now have your very own Keyoxide profile!

## Actually migrating to Keyoxide

Unfortunately, you get very little control when using your Keybase key directly. You will need to generate your own PGP keypair (use guides like [this one](https://spin.atomicobject.com/2013/11/24/secure-gpg-keys-guide/) for help) to unlock the full potential of [distributed identity proofs](/guides/proofs).

Have you generated a keypair and made the public key accessible through [web key directory (WKD)](/guides/web-key-directory) or uploaded it to [keys.openpgp.org](https://keys.openpgp.org/)? Use the [profile URL generator](/util/profile-url) to get your own profile URL and [start adding identity proofs](/guides).

## Keyoxide as a partial replacement for Keybase

It's important to moderate expectations and state that [Keyoxide](/) only replaces the subset of Keybase features that are considered the "core" features: message encryption, signature verification and identity proofs.

Message decryption and signing are **not** supported features: they would require you to upload your secret key to a website which is a big **no-no**.

Encrypted chat and cloud storage are **not** supported features: there are plenty of dedicated alternative services.

If you need any of these Keybase-specific supports, [Keyoxide](/) may not be a full Keybase replacement for you but you could still generate a profile and take advantage of **distributed identity proofs**.
