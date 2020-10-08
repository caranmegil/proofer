# How OpenPGP identity proofs work

[[toc]]

## Decentralized OpenPGP identity proofs

Decentralized OpenPGP identity proofs are the brainchild of Wiktor who wrote the original guide on [his website](https://metacode.biz/openpgp/proofs) (a suggested read to get first-hand information).

Unlike proofs provided by for example [Keybase](https://keybase.io), OpenPGP proofs are stored inside the PGP keys themselves instead of being mere signatures. Since this operation requires keys with "certify" capabilities and not simply "sign" capabilities, these OpenPGP proofs could be considered more secure.

## Example

*   Alice and Bob have been talking for years on service A. Alice already has an account on service B. Bob wants to move to service B as well. A simple decentralized proof confirms that the person who is known as Alice on service A is also known as Alice on service B. Bob can safely move to service B and talk to Alice without having to meet in person to confirm their accounts.
*   Alice has received a friend request from Bob29 on service C. Is this the same Bob from service A or not? A simple decentralized proof confirms that the person who is known as Bob on platform A is also known as Bob29 on service C. Turns out 28 Bobs were already using service C.
*   Bob has been invited by an account named Alyce to create an account on an unknown server. Is this a legit request? A simple decentralized proof tells Bob that Alice does not have such an account. Bob knows something is up and does not click the link possibly sent by an imposter.

## What an OpenPGP proof looks like

Every OpenPGP identity proof is stored in the PGP key as a notation that looks like this:

`proof@metacode.biz=https://twitter.com/USERNAME/status/1234567891234567891`

This particular proof is for a Twitter account (read more in the [Twitter guide](/guides/twitter)). Let's analyse the notation:

*   **proof** means the current notation is for an identity proof.
*   **@metacode.biz** is the domain of the person who came up with OpenPGP proofs and serves as a namespace for the notation. The domain is included and used for all proofs to comply with the [OpenPGP Message Format standard (RFC 4880)](https://tools.ietf.org/html/rfc4880#section-5.2.3.16).
*   **https://twitter.com/USERNAME/status/1234567891234567891** is the value of the notation. It is a link to the piece of online content that contains a pre-defined message which must always include the fingerprint of the PGP key that will hold the proof.

The proof should always link to a document that can be parsed as JSON to make the verification easy and feasible by the browser. Sometimes however, due to CORS restrictions or API requirements (as is the case for Twitter), no such link is provided by the platform. In these rare exceptional cases, the verification process is delegated to the Keyoxide server which will communicate directly with the platform's servers to get the content of the post.

## Your turn

If you'd like to add decentralized OpenPGP identity proofs to your key, go to the [guides](/guides) and find the right one for your platform of choice. You may find the process to be remarkably easy.

If your platform is not in the list of [guides](/guides), it's not supported yet. See the [contributing guide](/guides/contributing) for more information on how to get that platform supported.
