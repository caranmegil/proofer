# Uploading keys using web key directory

[[toc]]

## Web key directory

[Web key directory](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/) or WKD refers to the method of uploading one's public key to their website in a specific location to make it easily accessible by other services supporting WKD. The key will be discoverable using an identifier similar to an email address: **username@domain.org**.

The benefit of WKD is having full control over the key while still having it widely available. It does however require a domain and some form of file hosting. Luckily, [openpgp.org](https://keys.openpgp.org/about/usage#wkd-as-a-service) have made a WKD-as-a-service. Read more at the end of the guide.

It exists in two variants: the Direct setup and the Advanced setup. Despite their names, both require roughly the same steps.

## The Direct setup

To make your keys available via WKD using the Direct setup, you'll need two paths on your server:

**https://domain.org/.well-known/openpgpkey/policy**: this is an empty file

**https://domain.org/.well-known/openpgpkey/hu/LOCALPART**: this is the binary public key (so NOT ASCII armored)

The LOCALPART above is actually the username hashed using the SHA-1 algorithm and encoded using the Z-Base-32 method. As it's not humanly possible to compute this by ourselves, Keyoxide provides a [small utility to do this for you](/util/wkd).

So if you wish to make your key available as **jimothy@dm.com**, according to the [small utility](/util/wkd), the URL would become:

`https://dm.com/.well-known/openpgpkey/hu/n9utc41qty791upt63rm5xtiudabmw6m`

## The Advanced setup

While not necessary if the Direct setup works, there is a second setup to make WKD work: the Advanced setup. The paths needed are:

**https://openpgpkey.domain.org/.well-known/openpgpkey/domain.org/policy**: this is an empty file

**https://openpgpkey.domain.org/.well-known/openpgpkey/domain.org/hu/LOCALPART**: this is the binary public key (so NOT ASCII armored)

Indeed, quite similar to the Direct setup, except for the **openpgpkey** subdomain and the additional **domain.org** in the path of the public key.

The public key for **jimothy@dm.com** would be available at:

`https://openpgpkey.dm.com/.well-known/openpgpkey/hu/dm.com/n9utc41qty791upt63rm5xtiudabmw6m`

## WKD-as-a-service

In case hosting is problem, Openpgp.org has a handy [WKD-as-a-service](https://keys.openpgp.org/about/usage#wkd-as-a-service).
