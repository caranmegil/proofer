async function fetchKeys(opts) {
    // Init
    let lookupOpts, wkd, hkd, sig, lastPrimarySig;
    let output = {
        publicKey: null,
        user: null,
        notations: null,
        sigKeyId: null,
        sigUserId: null,
        sigContent: null
    };

    // Autodetect mode
    if (opts.mode == "auto") {
        if (/.*@.*\..*/.test(opts.input)) {
            opts.mode = "wkd";
        } else {
            opts.mode = "hkp";
        }
    }

    // Fetch keys depending on the input mode
    switch (opts.mode) {
        case "plaintext":
            output.publicKey = (await openpgp.key.readArmored(opts.input)).keys[0];

            if (!output.publicKey) {
                throw("Error: No public keys could be fetched from the plaintext input.");
            }
            break;

        case "wkd":
            wkd = new openpgp.WKD();
            lookupOpts = {
                email: opts.input
            };
            output.publicKey = (await wkd.lookup(lookupOpts)).keys[0];

            if (!output.publicKey) {
                throw("Error: No public keys could be fetched using WKD.");
            }
            break;

        case "hkp":
            if (!opts.server) {opts.server = "https://keys.openpgp.org/"};
            hkp = new openpgp.HKP(opts.server);
            lookupOpts = {
                query: opts.input
            };
            output.publicKey = await hkp.lookup(lookupOpts);
            output.publicKey = (await openpgp.key.readArmored(output.publicKey)).keys[0];

            if (!output.publicKey) {
                throw("Error: No public keys could be fetched from the HKP server.");
            }
            break;

        case "keybase":
            opts.keyLink = `https://keybase.io/${opts.username}/pgp_keys.asc?fingerprint=${opts.fingerprint}`;
            opts.input = `${opts.username}/${opts.fingerprint}`;
            try {
                opts.plaintext = await fetch(opts.keyLink).then(function(response) {
                    if (response.status === 200) {
                        return response;
                    }
                })
                .then(response => response.text());
            } catch (e) {
                throw(`Error: No public keys could be fetched from the Keybase account (${e}).`);
            }
            output.publicKey = (await openpgp.key.readArmored(opts.plaintext)).keys[0];

            if (!output.publicKey) {
                throw("Error: No public keys could be read from the Keybase account.");
            }
            break;

        case "signature":
            sig = (await openpgp.signature.readArmored(opts.signature));
            if ('compressed' in sig.packets[0]) {
                sig = sig.packets[0];
                output.sigContent = (await openpgp.stream.readToEnd(await sig.packets[1].getText()));
            };
            output.sigUserId = sig.packets[0].signersUserId;
            output.sigKeyId = (await sig.packets[0].issuerKeyId.toHex());

            if (!opts.server) {opts.server = "https://keys.openpgp.org/"};
            hkp = new openpgp.HKP(opts.server);
            lookupOpts = {
                query: output.sigUserId ? output.sigUserId : output.sigKeyId
            };
            output.publicKey = await hkp.lookup(lookupOpts);
            output.publicKey = (await openpgp.key.readArmored(output.publicKey)).keys[0];

            if (!output.publicKey) {
                throw("Error: No public keys could be extracted from the signature.");
            }
            break;
    }

    // Gather more data about the primary key and user
    output.fingerprint = await output.publicKey.primaryKey.getFingerprint();
    output.user = await output.publicKey.getPrimaryUser();
    lastPrimarySig = output.user.selfCertification;
    output.notations = lastPrimarySig.notations || [];

    return output;
}

async function verifyProof(url, fingerprint) {
    // Init
    let reVerify, match, output = {url: url, type: null, proofUrl: url, proofUrlFetch: null, isVerified: false, display: null, qr: null};

    // DNS
    if (/^dns:/.test(url)) {
        output.type = "domain";
        output.display = url.replace(/dns:/, '').replace(/\?type=TXT/, '');
        output.proofUrl = `https://dns.shivering-isles.com/dns-query?name=${output.display}&type=TXT`;
        output.proofUrlFetch = output.proofUrl;
        output.url = `https://${output.display}`;

        try {
            response = await fetch(output.proofUrlFetch, {
                headers: {
                    Accept: 'application/json'
                },
                credentials: 'omit'
            });
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            reVerify = new RegExp(`openpgp4fpr:${fingerprint}`, 'i');
            json.Answer.forEach((item, i) => {
                if (reVerify.test(item.data)) {
                    output.isVerified = true;
                }
            });
        } catch (e) {
        } finally {
            return output;
        }
    }
    // XMPP
    if (/^xmpp:/.test(url)) {
        output.type = "xmpp";
        match = url.match(/xmpp:([a-zA-Z0-9\.\-\_]*)@([a-zA-Z0-9\.\-\_]*)(?:\?(.*))?/);
        output.display = `${match[1]}@${match[2]}`;
        output.proofUrl = `https://PLACEHOLDER__XMPP_VCARD_SERVER_DOMAIN/api/vcard/${output.display}/DESC`;
        output.qr = url;

        try {
            response = await fetchWithTimeout(output.proofUrl);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            reVerify = new RegExp(`[Verifying my OpenPGP key: openpgp4fpr:${fingerprint}]`, 'i');
            if (reVerify.test(json)) {
                output.isVerified = true;
            }
        } catch (e) {
        } finally {
            return output;
        }
    }
    // Twitter
    if (/^https:\/\/twitter.com/.test(url)) {
        output.type = "twitter";
        match = url.match(/https:\/\/twitter\.com\/(.*)\/status\/([0-9]*)(?:\?.*)?/);
        output.display = `@${match[1]}`;
        output.url = `https://twitter.com/${match[1]}`;
        output.proofUrlFetch = `/server/verify/twitter
?tweetId=${encodeURIComponent(match[2])}
&account=${encodeURIComponent(match[1])}
&fingerprint=${fingerprint}`;
        try {
            response = await fetch(output.proofUrlFetch);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            output.isVerified = json.isVerified;
        } catch (e) {
        } finally {
            return output;
        }
    }

    // LemmyNet
    if (/lemmynet:https:\/\/.*\/u\/.*/.test(url)) {
        try {
            match = url.match(/lemmynet:(https:\/\/(.*)\/u\/(.*))/);
            if (match) {
                output.proofUrl = match[1];
                output.proofUrlFetch = `/server/verify/lemmynet?url=${encodeURIComponent(output.proofUrl)}&fingerprint=${fingerprint}`;
    
                try {
                    response = await fetch(output.proofUrlFetch);
                    if (!response.ok) {
                        throw new Error('Response failed: ' + response.status);
                    }
                    json = await response.json();
                    if (json.isVerified) {
                        output.type = "lemmynet";
                        output.display = `@${match[3]}@${match[2]}`;
                        output.isVerified = json.isVerified;
                    }
                    return output;
                } catch (e) {
                    console.warn(e);
                }
            }
        } catch (e) {
            console.warn(e);
        }
    }

    // Pixelfed
    if (/pixelfed\:https:\/\/.*\/(.*)/.test(url)) {
        try {
            match = url.match(/pixelfed\:(https:\/\/(.*)\/(.*))/);
            if (match) {
                output.proofUrl = match[1];
                output.proofUrlFetch = `/server/verify/pixelfed?url=${encodeURIComponent(output.proofUrl)}&fingerprint=${fingerprint}`;
    
                try {
                    response = await fetch(output.proofUrlFetch);
                    if (!response.ok) {
                        throw new Error('Response failed: ' + response.status);
                    }
                    json = await response.json();
                    if (json.isVerified) {
                        output.type = "pixelfed";
                        output.display = `@${match[3]}@${match[2]}`;
                        output.isVerified = json.isVerified;
                    }
                    return output;
                } catch (e) {
                    console.warn(e);
                }
            }
        } catch (e) {
            console.warn(e);
        }
    }

    // HN
    if (/^https:\/\/news.ycombinator.com/.test(url)) {
        output.type = "hackernews";
        match = url.match(/https:\/\/news.ycombinator.com\/user\?id=(.*)/);
        output.display = match[1];
        output.proofUrl = `https://hacker-news.firebaseio.com/v0/user/${match[1]}.json`;
        output.proofUrlFetch = output.proofUrl;
        try {
            response = await fetch(output.proofUrlFetch, {
                headers: {
                    Accept: 'application/json'
                },
                credentials: 'omit'
            });
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            reVerify = new RegExp(`openpgp4fpr:${fingerprint}`, 'i');
            if (reVerify.test(json.about)) {
                output.isVerified = true;
            }
        } catch (e) {
        }

        if (!output.isVerified) {
            output.proofUrlFetch = `/server/verify/proxy
?url=${encodeURIComponent(output.proofUrl)}
&fingerprint=${fingerprint}
&checkRelation=contains
&checkPath=about
&checkClaimFormat=message`;
            try {
                response = await fetch(output.proofUrlFetch);
                if (!response.ok) {
                    throw new Error('Response failed: ' + response.status);
                }
                json = await response.json();
                output.isVerified = json.verified;
            } catch (e) {
            }
        }
        return output;
    }
    // dev.to
    if (/^https:\/\/dev\.to\//.test(url)) {
        output.type = "dev.to";
        match = url.match(/https:\/\/dev\.to\/(.*)\/(.*)/);
        output.display = match[1];
        output.url = `https://dev.to/${match[1]}`;
        output.proofUrlFetch = `https://dev.to/api/articles/${match[1]}/${match[2]}`;
        try {
            response = await fetch(output.proofUrlFetch);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            reVerify = new RegExp(`[Verifying my OpenPGP key: openpgp4fpr:${fingerprint}]`, 'i');
            if (reVerify.test(json.body_markdown)) {
                output.isVerified = true;
            }
        } catch (e) {
        } finally {
            return output;
        }
    }
    // Reddit
    if (/^https:\/\/(?:www\.)?reddit\.com\/user/.test(url)) {
        output.type = "reddit";
        match = url.match(/https:\/\/(?:www\.)?reddit\.com\/user\/(.*)\/comments\/(.*)\/(.*)\//);
        output.display = match[1];
        output.url = `https://www.reddit.com/user/${match[1]}`;
        output.proofUrl = `https://www.reddit.com/user/${match[1]}/comments/${match[2]}.json`;
        output.proofUrlFetch = `/server/verify/proxy
?url=${encodeURIComponent(output.proofUrl)}
&fingerprint=${fingerprint}
&checkRelation=contains
&checkPath=data,children,data,selftext
&checkClaimFormat=message`;
        try {
            response = await fetch(output.proofUrlFetch);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            output.isVerified = json.isVerified;
        } catch (e) {
        } finally {
            return output;
        }
    }
    // Gitea
    if (/\/gitea_proof$/.test(url)) {
        output.type = "gitea";
        match = url.match(/https:\/\/(.*)\/(.*)\/gitea_proof/);
        output.display = `${match[2]}@${match[1]}`;
        output.url = `https://${match[1]}/${match[2]}`;
        output.proofUrl = `https://${match[1]}/api/v1/repos/${match[2]}/gitea_proof`;
        output.proofUrlFetch = `/server/verify/proxy
?url=${encodeURIComponent(output.proofUrl)}
&fingerprint=${fingerprint}
&checkRelation=eq
&checkPath=description
&checkClaimFormat=message`;
        output.proofUrl = url; // Actually set the proof URL to something user-friendly
        try {
            response = await fetch(output.proofUrlFetch);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            output.isVerified = json.isVerified;
        } catch (e) {
        } finally {
            return output;
        }
    }
    // Github
    if (/^https:\/\/gist.github.com/.test(url)) {
        output.type = "github";
        match = url.match(/https:\/\/gist.github.com\/(.*)\/(.*)/);
        output.display = match[1];
        output.url = `https://github.com/${match[1]}`;
        output.proofUrlFetch = `https://api.github.com/gists/${match[2]}`;
        try {
            response = await fetch(output.proofUrlFetch, {
                headers: {
                    Accept: 'application/json'
                },
                credentials: 'omit'
            });
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            reVerify = new RegExp(`[Verifying my OpenPGP key: openpgp4fpr:${fingerprint}]`, 'i');
            if (reVerify.test(json.files["openpgp.md"].content)) {
                output.isVerified = true;
            }
        } catch (e) {
        } finally {
            return output;
        }
    }
    // GitLab
    if (/\/gitlab_proof$/.test(url)) {
        output.type = "gitlab";
        match = url.match(/https:\/\/(.*)\/(.*)\/gitlab_proof/);
        output.display = `${match[2]}@${match[1]}`;
        output.url = `https://${match[1]}/${match[2]}`;
        output.proofUrlFetch = `https://${match[1]}/api/v4/users?username=${match[2]}`;
        try {
            const opts = {
                headers: {
                    Accept: 'application/json'
                },
                credentials: 'omit'
            };
            // Get user
            response = await fetch(output.proofUrlFetch, opts);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            const user = json.find(user => user.username === match[2]);
            if (!user) {
                throw new Error('No user with username ' + match[2]);
            }
            // Get project
            output.proofUrlFetch = `https://${match[1]}/api/v4/users/${user.id}/projects`;
            response = await fetch(output.proofUrlFetch, opts);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            const project = json.find(proj => proj.path === 'gitlab_proof');
            if (!project) {
                throw new Error('No project at ' + url);
            }
            reVerify = new RegExp(`[Verifying my OpenPGP key: openpgp4fpr:${fingerprint}]`, 'i');
            if (reVerify.test(project.description)) {
                output.isVerified = true;
            }
        } catch (e) {
        } finally {
            return output;
        }
    }
    // Lobsters
    if (/^https:\/\/lobste.rs/.test(url)) {
        output.type = "lobsters";
        match = url.match(/https:\/\/lobste.rs\/u\/(.*)/);
        output.display = match[1];
        output.proofUrl = `https://lobste.rs/u/${match[1]}.json`;
        output.proofUrlFetch = `/server/verify/proxy
?url=${encodeURIComponent(output.proofUrl)}
&fingerprint=${fingerprint}
&checkRelation=contains
&checkPath=about
&checkClaimFormat=message`;
        try {
            response = await fetch(output.proofUrlFetch);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            output.isVerified = json.isVerified;
        } catch (e) {
        } finally {
            return output;
        }
    }
    // Instagram
    if (/^https:\/\/www\.instagram\.com\/.*\//.test(url)) {
        output.type = "instagram";
        match = url.match(/https:\/\/www\.instagram\.com\/(.*)\//);
        output.display = match[1];
        output.proofUrl = url;
        output.proofUrlFetch = `/server/verify/instagram
?url=${encodeURIComponent(output.proofUrl)}
&fingerprint=${fingerprint}`;
        try {
            response = await fetch(output.proofUrlFetch);
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            output.isVerified = json.isVerified;
        } catch (e) {
        } finally {
            return output;
        }
    }
    // Catchall
    // Fediverse
    if (/https:\/\/.*\/@.*/.test(url) || /https:\/\/.*\/users\/.*/.test(url)) {
        try {
            response = await fetch(url, {
                headers: {
                    Accept: 'application/json'
                },
                credentials: 'omit'
            });
            if (!response.ok) {
                throw new Error('Response failed: ' + response.status);
            }
            json = await response.json();
            if ('attachment' in json) {
                match = url.match(/https:\/\/(.*)\/@(.*)/);
                if (match != null) {
                json.attachment.forEach((item, i) => {
                    reVerify = new RegExp(fingerprint, 'i');
                    if (reVerify.test(item.value)) {
                        output.type = "fediverse";
                        output.display = `@${json.preferredUsername}@${[match[1]]}`;
                        output.proofUrlFetch = json.url;
                        output.isVerified = true;
                    }
                });
                }
            }

            if (!output.type && 'summary' in json) {
                match = url.match(/https:\/\/(.*)\/users\/(.*)/);
                reVerify = new RegExp(`[Verifying my OpenPGP key: openpgp4fpr:${fingerprint}]`, 'i');
                if (reVerify.test(json.summary)) {
                    output.type = "fediverse";
                    output.display = `@${json.preferredUsername}@${[match[1]]}`;
                    output.proofUrlFetch = json.url;
                    output.isVerified = true;
                }
            }
            if (output.type) {
                return output;
            }
        } catch (e) {
            console.warn(e);
        }
    }
    // Discourse
    try {
        match = url.match(/https:\/\/(.*)\/u\/(.*)/);
        if (match) {
            output.proofUrl = `${url}.json`;
            output.proofUrlFetch = `/server/verify/proxy
    ?url=${encodeURIComponent(output.proofUrl)}
    &fingerprint=${fingerprint}
    &checkRelation=contains
    &checkPath=user,bio_raw
    &checkClaimFormat=message`;
            try {
                response = await fetch(output.proofUrlFetch);
                if (!response.ok) {
                    throw new Error('Response failed: ' + response.status);
                }
                json = await response.json();
                if (json.isVerified) {
                    output.type = "discourse";
                    output.display = `${match[2]}@${match[1]}`;
                    output.isVerified = json.isVerified;
                    return output;
                }
            } catch (e) {
                console.warn(e);
            }
        }
    } catch (e) {
        console.warn(e);
    }

    // Return output without confirmed proof
    return output;
}
