# Encrypting a message

Let's see how to encrypt a message.

[[toc]]

## Obtain a public key for encryption

The idea is that you use someone's public key to encrypt a message. From then on, the message cannot be decrypted and read by anyone but the person possessing the private keys associated with the public key (they'll have the same fingerprint).

If you already have a public key (or its fingerprint) you would like to use to encrypt a message, great! If not, you could use the following fingerprint:

`9f0048ac0b23301e1f77e994909f6bd6f80f485d`

## Encrypt a message

Open the [/encrypt](/encrypt) page and paste the fingerprint in the **Email / key id / fingerprint** field.

Write a message in the **Message** field. Scroll down and press the **ENCRYPT MESSAGE** button.

You have successfully encrypted the message! The encrypted message in the **Message** field can safely be sent via unsecured communication channels knowing that only the person possessing the private key associated with that fingerprint can read it.

## Going further

You could try using different mechanisms of fetching keys, such as **web key directory** or copy-pasting a plaintext public key.

If you'd like to receive PGP encrypted messages, you must first learn the fundamentals of PGP and how to generate and handle your own keypair.
