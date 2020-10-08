# Verifying identity proofs

Let's see how to verify identity proofs.

[[toc]]

## Obtain a public key for verification

The idea is that anyone can add identity proofs of various platforms in their keys. Since this information is kept in the public key, you could take anyone's public key and check whether they indeed have control over the accounts they claim to.

If you already have a public key (or its fingerprint) with OpenPGP identity proofs you would like to use to verify, great! If not, you could use the following fingerprint:

`9f0048ac0b23301e1f77e994909f6bd6f80f485d`

## Verify proofs

Open the [keyoxide.org/proofs](/proofs) page and paste the fingerprint in the **Email / key id / fingerprint** field. Scroll down and press the **VERIFY PROOFS** button.

You now see a list of domains and/or accounts on platforms for which the owner of the public key claims to have an control over.

If the last link on a line says **proof**, the proof could not be verified for any number of reasons but Keyoxide still allows to check the supposed proof and decide for yourself whether you trust the claim. If the

If the last link on a line says **verified**, the owner of the public key indeed has shown beyond doubt that it has control over the domain or account.

## Your turn

If you'd like to add decentralized OpenPGP identity proofs to your key, go to the [guides](/guides) and find the right one for your platform of choice. You may find the process to be remarkably easy.

If your platform is not in the list of [guides](/guides), it's not supported yet. See the [contributing guide](/guides/contributing) for more information on how to get that platform supported.
