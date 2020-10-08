# Feature comparison with Keybase

Let's see how Keyoxide's features compare to those of Keybase.

[[toc]]

## Encrypt and verify

Both Keyoxide and Keybase allow easy encryption of data and verification of signatures. While Keybase can only perform these actions for their users who uploaded at least a public key to their servers, Keyoxide can do this for any key on the internet, whether it's available through web key directory, dedicated key servers or simply copy-pasting a plaintext key.

## Decrypt and sign

Keyoxide cannot decrypt data or sign messages.

Keybase can do both of those things but this should NOT be considered a feature. It requires one to upload their private key to closed-source servers which is an act in stark contradiction with all safety precautions any owner of a private key should aim to heed.

## Online identity proofs

Both Keyoxide and Keybase allow the user to generate proofs of online identity on various platforms. The difference lies in the method of generation and the implications this has on security.

Keybase generates a signed message to be posted by the to-be-verified account. Since this involves a signature, any signing key can be used. If a signing key gets misappropriated, it becomes easy for a bad actor to create fake identity proofs.

Keyoxide uses decentralized OpenPGP proofs in which the identity proofs are stored as notations within the keys themselves. This is only possible when you have access to keys with "certification" capability. As these are the most valuable of keys, they should also be handled more securely than signing keys and are therefore less prone to forgery of identity proofs.

## Social network and additional services

Keybase provides an additional social network, chat functionality, encrypted drive, encrypted git, XLM crypto wallet and much more.

Keyoxide has none of that. Just keys and proofs.

## Openness

Keyoxide is fully open-source. It consists mainly of a client component which is the browser. The supporting server functions are open-source as well.

Keybase has open-source clients but closed-source servers.

## Data safety

Keyoxide lets the user's devices do almost all of the heavy lifting, meaning no data is ever sent to a server to perform any of the actions. Only exceptions to this rule are a couple of "proxy scripts" for proofs that cannot be verified by a browser. These proxy scripts are open-source as well and inspectable by all.

Keybase servers are closed-source. One does not know what happens inside that black box.
