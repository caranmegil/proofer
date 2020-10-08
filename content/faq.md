# FAQ

[[toc]]

## What is Keyoxide?

[Keyoxide](/) is a modern and privacy-friendly platform to establish your decentralized online identity. It is fully Open Source under an AGPLv3 license and it can even be self-hosted. It can also perform basic cryptographic operations like encryption and signature verification.

## Why does Keyoxide exist?

[Keyoxide](/) helps solve a growing issue on today's internet: **identity**.

During the *Web 1.0* days of the internet shortly after its inception, it served as a new world for people to explore. **Anonymity** reigned as all websites were silos: you could be two completely different personas on two different sites. You could even have different personas on the same website. There was no method to link personas to our real-world identity, nor a reason to.

Entered the *Web 2.0*. Small sites disappeared as large corporations took over. Facebook, Google, Amazon. Creating an account on those platforms had a lot of implications: that single account could be used across their different services and with the creation of "Login with X" buttons, even across different websites. People gave these platforms their personal information, a name, a phone number. That one account defined who you were on the internet. The corporation behind the platform had become the guardian of our online **identity**. As the internet slowly invaded our real-world lives, so did these platforms. We trusted them. We became complacent.

We know better now. These internet corporations gave us convenience with one hand and took away our privacy with the other. But we are getting a third chance.

Developers all over the world are building the *Web 3.0*, a new vision of the internet where its citizens keep control over their data and, by extension, their **identity**. The internet is only growing bigger and becoming a larger part of our lives. This new Web will have a strong focus on both **anonymity** and **identity**. [Keyoxide](/) is here to help with the latter.

While **anonymity** is the art of keeping a persona devoid of individualizing characteristics or qualities, **identity** is the science of tying online entities together, making sure the world can see these entities are part of a larger persona. A person can have multiple personas, or online **identities**.

## How does Keyoxide work?

### The simple explanation

You create a special secure document that only you can edit, containing a list of accounts that you have created: one of these accounts is, let's say, a Twitter account. At the same time, you also a little piece of text to, for example, your Twitter bio, containing the name of that same document. [Keyoxide](/) reads this special document, sees you have a Twitter account, has a look at that account and finds the name of your document.

Because this is only possible if one and the same person has access to both that special document and the Twitter account, we have now verified this account belonging to you. If you add other accounts, you get a profile page which people can use to know who you are on different websites.

### The complicated explanation

Cryptographic keypairs consist of a private key and a public key. While both keys contain the same information, the private key allows one to edit the contents of the keypair and the public key allows one to simply read the contents of the keypair.

This makes cryptographic keypairs a perfect vessel for online identities. Only one person can add so-called &quot;proofs&quot; to the keypair while the rest of the world can only read the proofs. The same is true for accounts on websites: the whole world can see your profile while only you can make changes to it.

Proofs are stored inside keypairs as so-called &quot;notations&quot;: these can be seen as custom data entries. Typically, proofs are structured as follows:

`proof@metacode.biz=https://platform.com/username`

- *proof* tells us we are looking at a proof.
- *@metacode.biz* tells us this is a specific type of proof, as defined on the [metacode.biz website](https://metacode.biz/openpgp/proofs). This part should NOT be changed when adding a new proof to your key.
- The rest of the proof is simply a URL to the profile page of your account on a website.

It is important to note that not all websites are supported. For now, supporting a single online platform involves quite a bit of manual work. It is also important to note not all platforms can be supported. You can always suggest new platforms to support by [creating an issue here](https://codeberg.org/keyoxide/) or contacting me at [yarmo@keyoxide.org](mailto:yarmo@keyoxide.org).

## How does Keyoxide fit in the Web 3.0?

The one word to associate with the Web 3.0 is **decentralization**. This indirectly refers to the process of separating applications from data.

This means that while [Keyoxide](/) (the application) does the verification of your identity, it should not store that identity on its server! The data associated with your identity is stored in a different place where you keep control over it, typically a dedicated key server. We strongly  recommend [keys.openpgp.org](https://keys.openpgp.org/) which is the default key server [Keyoxide](/).

## How can I make an account?

You can't and that is the whole point of [Keyoxide](/). Your data and your keys are not stored on our server. Therefore, there is no need to create an account. You simply [create a cryptographic keypair](/getting-started) and upload it to a dedicated key server. [Keyoxide](/) will automatically fetch your key only when needed.

## Can I get a sweet profile page?

That, we can help you with! Just append the fingerprint of your keypair to the domain like so: [https://${domain}/9f0048ac0b23301e1f77e994909f6bd6f80f485d](/9f0048ac0b23301e1f77e994909f6bd6f80f485d) to generate a profile page.

## Where is my profile avatar?

There are currently two methods of getting an avatar displayed on your profile page:

1. automatically fetched from Gravatar using your primary email address;
2. extracted from the public key.

While the first method is the simplest, the slightly-more-complicated second method provides an additional layer of privacy protection by not having to upload your profile picture to a 3rd party.

One caveat: [keys.openpgp.org](https://keys.openpgp.org) strips images from public keys. So the second method will only work in conjunction with [Web Key Directory](/guides/web-key-directory).

## Where do I upload my private key?

**DON'T**! We don't want it!

Alternative services may ask you for your private keys so that they can offer additional functionality. Please understand that your private key is yours and ONLY yours. You should never upload it to any online service, in fact it should never leave your computer.

## Where is the app?

There is no app yet. This is on the [roadmap](#what-is-on-the-roadmap%3F).

## PGP must die!

Not a question but we get your point. While there are [legitimate reasons PGP should not be used for use cases like communication](https://restoreprivacy.com/let-pgp-die/), it is still widely used and is actually quite a good fit for decentralized identity management.

But yes, try to avoid OpenPGP for communication. There are plenty of (decentralized) encrypted messaging platforms out there much better suited to that task.

## What is on the roadmap?

- Create apps
- Create an API
- Make Keyoxide more accessible (a11y and i18n)
- Support more platforms and services
- Integrate other encryption programs
