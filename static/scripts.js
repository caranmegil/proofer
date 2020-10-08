/*
Copyright (C) 2020 Yarmo Mackenbach

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option)
any later version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

If your software can interact with users remotely through a computer network,
you should also make sure that it provides a way for users to get its source.
For example, if your program is a web application, its interface could display
a "Source" link that leads users to an archive of the code. There are many
ways you could offer source, and different solutions will be better for different
programs; see section 13 for the specific requirements.

You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary. For
more information on this, and how to apply and follow the GNU AGPL, see <https://www.gnu.org/licenses/>.
*/
async function verifySignature(opts) {
    // Init
    const elRes = document.body.querySelector("#result");
    const elResContent = document.body.querySelector("#resultContent");
    let keyData, feedback, signature, verified, valid;

    // Reset feedback
    elRes.innerHTML = "";
    elRes.classList.remove('green');
    elRes.classList.remove('red');
    elResContent.innerHTML = "";

    try {
        // Get key data
        keyData = await fetchKeys(opts);

        // Handle missing signature
        if (opts.signature == null) { throw("No signature was provided."); }

        // Try two different methods of signature reading
        let readError = null;
        try {
            signature = await openpgp.message.readArmored(opts.signature);
        } catch(e) {
            readError = e;
        }
        try {
            signature = await openpgp.cleartext.readArmored(opts.signature);
        } catch(e) {
            readError = e;
        }
        if (signature == null) { throw(readError) };

        // Verify the signature
        verified = await openpgp.verify({
            message: signature,
            publicKeys: keyData.publicKey
        });
        valid = verified.signatures[0].valid;
    } catch (e) {
        console.error(e);
        elRes.innerHTML = e;
        elRes.classList.remove('green');
        elRes.classList.add('red');
        return;
    }

    // Init feedback to empty string
    feedback = '';

    // If content was extracted from signature
    if (keyData.sigContent) {
        elResContent.innerHTML = "<strong>Signature content:</strong><br><span style=\"white-space: pre-line\">"+sigContent+"</span>";
    }

    // Provide different feedback depending on key input mode
    if (opts.mode == "signature" && keyData.sigUserId) {
        if (valid) {
            feedback += "The message was signed by the userId extracted from the signature.<br>";
            feedback += 'UserId: '+keyData.sigUserId+'<br>';
            feedback += "Fingerprint: "+keyData.fingerprint+"<br>";
            elRes.classList.remove('red');
            elRes.classList.add('green');
        } else {
            feedback += "The message's signature COULD NOT BE verified using the userId extracted from the signature.<br>";
            feedback += 'UserId: '+keyData.sigUserId+'<br>';
            elRes.classList.remove('green');
            elRes.classList.add('red');
        }
    } else if (opts.mode == "signature" && keyData.sigKeyId) {
        if (valid) {
            feedback += "The message was signed by the keyId extracted from the signature.<br>";
            feedback += 'KeyID: '+keyData.sigKeyId+'<br>';
            feedback += "Fingerprint: "+keyData.fingerprint+"<br><br>";
            feedback += "!!! You should manually verify the fingerprint to confirm the signer's identity !!!";
            elRes.classList.remove('red');
            elRes.classList.add('green');
        } else {
            feedback += "The message's signature COULD NOT BE verified using the keyId extracted from the signature.<br>";
            feedback += 'KeyID: '+keyData.sigKeyId+'<br>';
            elRes.classList.remove('green');
            elRes.classList.add('red');
        }
    } else {
        if (valid) {
            feedback += "The message was signed by the provided key ("+opts.mode+").<br>";
            feedback += "Fingerprint: "+keyData.fingerprint+"<br>";
            elRes.classList.remove('red');
            elRes.classList.add('green');
        } else {
            feedback += "The message's signature COULD NOT BE verified using the provided key ("+opts.mode+").<br>";
            elRes.classList.remove('green');
            elRes.classList.add('red');
        }
    }

    // Display feedback
    elRes.innerHTML = feedback;
};

async function encryptMessage(opts) {
    // Init
    const elEnc = document.body.querySelector("#message");
    const elRes = document.body.querySelector("#result");
    const elBtn = document.body.querySelector("[name='submit']");
    let keyData, feedback, message, encrypted;

    // Reset feedback
    elRes.innerHTML = "";
    elRes.classList.remove('green');
    elRes.classList.remove('red');

    try {
        // Get key data
        keyData = await fetchKeys(opts);

        // Handle missing message
        if (opts.message == null) {
            throw("No message was provided.");
        }

        // Encrypt the message
        encrypted = await openpgp.encrypt({
            message: openpgp.message.fromText(opts.message),
            publicKeys: keyData.publicKey
        });
    } catch (e) {
        console.error(e);
        elRes.innerHTML = e;
        elRes.classList.remove('green');
        elRes.classList.add('red');
        return;
    }

    // Display encrypted data
    elEnc.value = encrypted.data;
    elEnc.toggleAttribute("readonly");
    elBtn.setAttribute("disabled", "true");
};

async function verifyProofs(opts) {
    // Init
    const elRes = document.body.querySelector("#result");
    let keyData, feedback = "", message, encrypted;

    // Reset feedback
    elRes.innerHTML = "";
    elRes.classList.remove('green');
    elRes.classList.remove('red');

    try {
        // Get key data
        keyData = await fetchKeys(opts);
    } catch (e) {
        console.error(e);
        elRes.innerHTML = e;
        elRes.classList.remove('green');
        elRes.classList.add('red');
        return;
    }

    let notationsRaw = [];
    for (var i = 0; i < keyData.publicKey.users.length; i++) {
        notationsRaw = notationsRaw.concat(keyData.publicKey.users[i].selfCertifications[0].notations);
    }

    let verifications = [];

    for(var i = 0; i < notationsRaw.length; i++) {
        var item = notationsRaw[i]
        if (item[0] == "proof@metacode.biz") {
            verifications.push(await verifyProof(item[1], keyData.fingerprint));
        }
    };

    // Display feedback
    elRes.innerHTML = "Verifying proofs&hellip;";

    // One-line sorting function (order verifications by type)
    verifications = verifications.sort((a,b) => (a.type > b.type) ? 1 : ((b.type > a.type) ? -1 : 0));

    // Generate feedback
    for (var i = 0; i < verifications.length; i++) {
        if (verifications[i].type == null) { continue; }
        feedback += `${verifications[i].type}: `;
        feedback += `<a class="proofDisplay" href="${verifications[i].url}" rel="me">${verifications[i].display}</a> `;
        if (verifications[i].isVerified) {
            feedback += `<a class="proofUrl proofUrl--verified" href="${verifications[i].proofUrl}">verified &#10004;</a>`;
        } else {
            feedback += `<a class="proofUrl" href="${verifications[i].proofUrl}">unverified</a>`;
        }
        feedback += `<br>`;
    }
    feedback += `</p>`;

    // Display feedback
    elRes.innerHTML = feedback;
}

async function displayProfile(opts) {
    let keyData, keyLink, feedback = "", notation, isVerified, verifications = [];
    let icon_qr = '<svg style="width:24px;height:24px" viewBox="0 0 24 24"><path fill="#ffffff" d="M3,11H5V13H3V11M11,5H13V9H11V5M9,11H13V15H11V13H9V11M15,11H17V13H19V11H21V13H19V15H21V19H19V21H17V19H13V21H11V17H15V15H17V13H15V11M19,19V15H17V19H19M15,3H21V9H15V3M17,5V7H19V5H17M3,3H9V9H3V3M5,5V7H7V5H5M3,15H9V21H3V15M5,17V19H7V17H5Z" /></svg>';

    try {
        keyData = await fetchKeys(opts);
    } catch (e) {
        feedback += `<p>There was a problem fetching the keys.</p>`;
        feedback += `<code>${e}</code>`;
        document.body.querySelector('#profileData').innerHTML = feedback;
        document.body.querySelector('#profileName').innerHTML = "Could not load profile";
        return;
    }

    let userData = keyData.user.user.userId;
    let userName = userData.name ? userData.name : userData.email;
    let userMail = userData.email ? userData.email : null;

    let imgUri = null;

    let notations = [], notationsRaw = [];
    for (var i = 0; i < keyData.publicKey.users.length; i++) {
        if (keyData.publicKey.users[i].selfCertifications.length == 0) { continue; }

        notationsRaw = notationsRaw.concat(keyData.publicKey.users[i].selfCertifications[0].notations);

        if (keyData.publicKey.users[i].userAttribute != null && keyData.publicKey.users[i].userAttribute.attributes[0][0] === String.fromCharCode(1)) {
            imgUri = "data:image/jpeg;base64," + btoa(keyData.publicKey.users[i].userAttribute.attributes[0].substring(17));
        }
    }
    notationsRaw.forEach((item, i) => {
        if (item[0] == "proof@metacode.biz") {
            notations.push(item[1]);
        }
    });
    notations = Array.from(new Set(notations)); // Deduplicate (ES6)

    // Determine WKD or HKP link
    switch (opts.mode) {
        case "wkd":
            const [, localPart, domain] = /(.*)@(.*)/.exec(opts.input);
            const localEncoded = await computeWKDLocalPart(localPart.toLowerCase());
            const urlAdvanced = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${localEncoded}`;
            const urlDirect = `https://${domain}/.well-known/openpgpkey/hu/${localEncoded}`;

            try {
                keyLink = await fetch(urlAdvanced).then(function(response) {
                    if (response.status === 200) {
                        return urlAdvanced;
                    }
                });
            } catch (e) {
                console.warn(e);
            }
            if (!keyLink) {
                try {
                    keyLink = await fetch(urlDirect).then(function(response) {
                        if (response.status === 200) {
                            return urlDirect;
                        }
                    });
                } catch (e) {
                    console.warn(e);
                }
            }
            if (!keyLink) {
                keyLink = `https://keys.openpgp.org/pks/lookup?op=get&options=mr&search=0x${keyData.fingerprint}`;
            }
            break;

        case "hkp":
            keyLink = `https://keys.openpgp.org/pks/lookup?op=get&options=mr&search=0x${keyData.fingerprint}`;
            break;

        case "keybase":
            keyLink = opts.keyLink;
            break;
    }

    // Fill in various data
    document.body.querySelector('#profileName').innerHTML = userName;
    document.body.querySelector('#profileAvatar').style = "";
    const profileHash = openpgp.util.str_to_hex(openpgp.util.Uint8Array_to_str(await openpgp.crypto.hash.md5(openpgp.util.str_to_Uint8Array(userData.email))));
    if (imgUri) {
        document.body.querySelector('#profileAvatar').src = imgUri;
    } else {
        document.body.querySelector('#profileAvatar').src = `https://www.gravatar.com/avatar/${profileHash}?s=128&d=mm`;
    }
    document.title = `${userName} - Keyoxide`;

    // Generate feedback
    feedback += `<div class="profileDataItem profileDataItem--separator profileDataItem--noLabel">`;
    feedback += `<div class="profileDataItem__label"></div>`;
    feedback += `<div class="profileDataItem__value">general information</div>`;
    feedback += `</div>`;
    if (userMail) {
      feedback += `<div class="profileDataItem">`;
      feedback += `<div class="profileDataItem__label">primary email</div>`;
      feedback += `<div class="profileDataItem__value"><a href="mailto:${userMail}">${userMail}</a></div>`;
      feedback += `</div>`;
    }
    for (var i = 0; i < keyData.publicKey.users.length; i++) {
        if (keyData.publicKey.users[i].userId && 'email' in keyData.publicKey.users[i].userId && keyData.publicKey.users[i].userId.email && keyData.publicKey.users[i].revocationSignatures.length == 0 && keyData.publicKey.users[i].userId.email != userMail) {
            feedback += `<div class="profileDataItem">`;
            feedback += `<div class="profileDataItem__label">email</div>`;
            feedback += `<div class="profileDataItem__value"><a href="mailto:${keyData.publicKey.users[i].userId.email}">${keyData.publicKey.users[i].userId.email}</a></div>`;
            feedback += `</div>`;
        }
    }
    feedback += `<div class="profileDataItem">`;
    feedback += `<div class="profileDataItem__label">fingerprint</div>`;
    feedback += `<div class="profileDataItem__value"><a href="${keyLink}">${keyData.fingerprint}</a>`;
    if (opts.mode == "hkp") {
        feedback += `<a class="proofQR green" href="/util/qr/${encodeURIComponent(`OPENPGP4FPR:${keyData.fingerprint.toUpperCase()}`)}" target="_blank" title="QR Code">${icon_qr}</a>`;
    }
    feedback += `</div></div>`;

    // if (opts.mode == "hkp") {
    //     feedback += `<div class="profileDataItem">`;
    //     feedback += `<div class="profileDataItem__label">qrcode</div>`;
    //     feedback += `<div class="profileDataItem__value"><a class="green" href="/util/qr/${encodeURIComponent(`OPENPGP4FPR:${keyData.fingerprint.toUpperCase()}`)}" target="_blank">fingerprint</a></div>`;
    //     feedback += `</div>`;
    // }

    if (notations.length > 0) {
        feedback += `<div class="profileDataItem profileDataItem--separator profileDataItem--noLabel">`;
        feedback += `<div class="profileDataItem__label"></div>`;
        feedback += `<div class="profileDataItem__value">proofs</div>`;
        feedback += `</div>`;

        feedback += `<div id="profileProofs">`;
        feedback += `<div class="profileDataItem  profileDataItem--noLabel">`;
        feedback += `<div class="profileDataItem__label"></div>`;
        feedback += `<div class="profileDataItem__value">Verifying proofs&hellip;</div>`;
        feedback += `</div>`;
        feedback += `</div>`;
    }

    feedback += `<div class="profileDataItem profileDataItem--separator profileDataItem--noLabel">`;
    feedback += `<div class="profileDataItem__label"></div>`;
    feedback += `<div class="profileDataItem__value">actions</div>`;
    feedback += `</div>`;
    feedback += `<div class="profileDataItem profileDataItem--noLabel">`;
    feedback += `<div class="profileDataItem__label"></div>`;
    feedback += `<div class="profileDataItem__value"><a href="/verify/${opts.mode}/${opts.input}">verify signature</a></div>`;
    feedback += `</div>`;
    feedback += `<div class="profileDataItem profileDataItem--noLabel">`;
    feedback += `<div class="profileDataItem__label"></div>`;
    feedback += `<div class="profileDataItem__value"><a href="/encrypt/${opts.mode}/${opts.input}">encrypt message</a></div>`;
    feedback += `</div>`;

    // Display feedback
    document.body.querySelector('#profileData').innerHTML = feedback;

    // Exit if no notations are available
    if (notations.length == 0) {
        return;
    }

    // Verify identity proofs
    let proofResult;
    for (var i = 0; i < notations.length; i++) {
        notation = notations[i];
        proofResult = await verifyProof(notation, keyData.fingerprint);
        if (!proofResult || !proofResult.display) { continue; }
        verifications.push(proofResult);
    }

    // One-line sorting function (order verifications by type)
    verifications = verifications.sort((a,b) => (a.type > b.type) ? 1 : ((b.type > a.type) ? -1 : 0));

    feedback = "";
    if (verifications.length > 0) {
        for (var i = 0; i < verifications.length; i++) {
            if (!verifications[i].type) { continue; }
            feedback += `<div class="profileDataItem">`;
            feedback += `<div class="profileDataItem__label">${verifications[i].type}</div>`;
            feedback += `<div class="profileDataItem__value">`;
            feedback += `<a class="proofDisplay" href="${verifications[i].url}"  rel="me">${verifications[i].display}</a>`;
            if (verifications[i].isVerified) {
                feedback += `<a class="proofUrl proofUrl--verified" href="${verifications[i].proofUrl}">verified &#10004;</a>`;
            } else {
                feedback += `<a class="proofUrl" href="${verifications[i].proofUrl}">unverified</a>`;
            }
            if (verifications[i].isVerified && verifications[i].qr) {
                feedback += `<a class="proofQR green" href="/util/qr/${encodeURIComponent(verifications[i].qr)}" target="_blank" title="QR Code">${icon_qr}</a>`;
            }
            feedback += `</div>`;
            feedback += `</div>`;
        }
    } else {
        feedback += `<div class="profileDataItem  profileDataItem--noLabel">`;
        feedback += `<div class="profileDataItem__label"></div>`;
        feedback += `<div class="profileDataItem__value">No proofs found in key</div>`;
        feedback += `</div>`;
    }

    // Display feedback
    document.body.querySelector('#profileProofs').innerHTML = feedback;
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

function encodeZBase32(data) {
    // Source: https://github.com/openpgpjs/openpgpjs/blob/master/src/util.js
    if (data.length === 0) {
        return "";
    }
    const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
    const SHIFT = 5;
    const MASK = 31;
    let buffer = data[0];
    let index = 1;
    let bitsLeft = 8;
    let result = '';
    while (bitsLeft > 0 || index < data.length) {
        if (bitsLeft < SHIFT) {
            if (index < data.length) {
                buffer <<= 8;
                buffer |= data[index++] & 0xff;
                bitsLeft += 8;
            } else {
                const pad = SHIFT - bitsLeft;
                buffer <<= pad;
                bitsLeft += pad;
            }
        }
        bitsLeft -= SHIFT;
        result += ALPHABET[MASK & (buffer >> bitsLeft)];
    }
    return result;
}

async function computeWKDLocalPart(message) {
    const data = openpgp.util.str_to_Uint8Array(message);
    const hash = await openpgp.crypto.hash.sha1(data);
    return openpgp.util.encodeZBase32(hash);
}

async function generateProfileURL(data) {
    let hostname = window.location.hostname;

    if (data.input == "") {
        return "Waiting for input...";
    }
    switch (data.source) {
        case "wkd":
            return `https://${hostname}/${data.input}`;
            break;
        case "hkp":
            if (/.*@.*\..*/.test(data.input)) {
                return `https://${hostname}/hkp/${data.input}`;
            } else {
                return `https://${hostname}/${data.input}`;
            }
            break;
        case "keybase":
            const re = /https\:\/\/keybase.io\/(.*)\/pgp_keys\.asc\?fingerprint\=(.*)/;
            if (!re.test(data.input)) {
                return "Incorrect Keybase public key URL.";
            }
            const match = data.input.match(re);
            return `https://${hostname}/keybase/${match[1]}/${match[2]}`;
            break;
    }
}

async function fetchWithTimeout(url, timeout = 3000) {
    return Promise.race([
        fetch(url),
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error('timeout')), timeout)
        )
    ]);
}

// General purpose
let elFormVerify = document.body.querySelector("#form-verify"),
    elFormEncrypt = document.body.querySelector("#form-encrypt"),
    elFormProofs = document.body.querySelector("#form-proofs"),
    elProfileUid = document.body.querySelector("#profileUid"),
    elProfileMode = document.body.querySelector("#profileMode"),
    elModeSelect = document.body.querySelector("#modeSelect"),
    elUtilWKD = document.body.querySelector("#form-util-wkd"),
    elUtilQRFP = document.body.querySelector("#form-util-qrfp"),
    elUtilQR = document.body.querySelector("#form-util-qr"),
    elUtilProfileURL = document.body.querySelector("#form-util-profile-url");

if (elModeSelect) {
    elModeSelect.onchange = function (evt) {
        let elAllModes = document.body.querySelectorAll('.modes');
        elAllModes.forEach(function(el) {
            el.classList.remove('modes--visible');
        });
        document.body.querySelector(`.modes--${elModeSelect.value}`).classList.add('modes--visible');
    }
    elModeSelect.dispatchEvent(new Event("change"));
}

if (elFormVerify) {
    elFormVerify.onsubmit = function (evt) {
        evt.preventDefault();

        let opts = {
            signature: null,
            mode: null,
            input: null,
            server: null,
        };

        opts.signature = document.body.querySelector("#signature").value;
        opts.mode = document.body.querySelector("#modeSelect").value;

        switch (opts.mode) {
            default:
            case "auto":
                opts.input = document.body.querySelector("#auto_input").value;
                break;

            case "wkd":
                opts.input = document.body.querySelector("#wkd_input").value;
                break;

            case "hkp":
                opts.input = document.body.querySelector("#hkp_input").value;
                opts.server =  document.body.querySelector("#hkp_server").value;
                break;

            case "plaintext":
                opts.input = document.body.querySelector("#plaintext_input").value;
                break;

            case "keybase":
                opts.username = document.body.querySelector("#keybase_username").value;
                opts.fingerprint =  document.body.querySelector("#keybase_fingerprint").value;
                break;
        }

        // If no input was detect
        if (!opts.input && !opts.username) {
            opts.mode = "signature";
        }

        verifySignature(opts);
    };
}

if (elFormEncrypt) {
    elFormEncrypt.onsubmit = function (evt) {
        evt.preventDefault();

        let opts = {
            message: null,
            mode: null,
            input: null,
            server: null,
        };

        opts.message = document.body.querySelector("#message").value;
        opts.mode = document.body.querySelector("#modeSelect").value;

        switch (opts.mode) {
            default:
            case "auto":
                opts.input = document.body.querySelector("#auto_input").value;
                break;

            case "wkd":
                opts.input = document.body.querySelector("#wkd_input").value;
                break;

            case "hkp":
                opts.input = document.body.querySelector("#hkp_input").value;
                opts.server =  document.body.querySelector("#hkp_server").value;
                break;

            case "plaintext":
                opts.input = document.body.querySelector("#plaintext_input").value;
                break;

            case "keybase":
                opts.username = document.body.querySelector("#keybase_username").value;
                opts.fingerprint =  document.body.querySelector("#keybase_fingerprint").value;
                break;
        }

        encryptMessage(opts);
    };
}

if (elFormProofs) {
    elFormProofs.onsubmit = function (evt) {
        evt.preventDefault();

        let opts = {
            mode: null,
            input: null,
            server: null,
        };

        opts.mode = document.body.querySelector("#modeSelect").value;

        switch (opts.mode) {
            default:
            case "auto":
                opts.input = document.body.querySelector("#auto_input").value;
                break;

            case "wkd":
                opts.input = document.body.querySelector("#wkd_input").value;
                break;

            case "hkp":
                opts.input = document.body.querySelector("#hkp_input").value;
                opts.server =  document.body.querySelector("#hkp_server").value;
                break;

            case "plaintext":
                opts.input = document.body.querySelector("#plaintext_input").value;
                break;
        }

        verifyProofs(opts);
    };
}

if (elProfileUid) {
    let match, opts, profileUid = elProfileUid.innerHTML;
    switch (elProfileMode.innerHTML) {
        default:
        case "auto":
            if (/.*@.*/.test(profileUid)) {
                // Match email for wkd
                opts = {
                    input: profileUid,
                    mode: "wkd"
                }
            } else {
                // Match fingerprint for hkp
                opts = {
                    input: profileUid,
                    mode: "hkp"
                }
            }
            break;

        case "hkp":
        case "wkd":
            opts = {
                input: profileUid,
                mode: elProfileMode.innerHTML
            }
            break;

        case "keybase":
            let match = profileUid.match(/(.*)\/(.*)/);
            opts = {
                username: match[1],
                fingerprint: match[2],
                mode: elProfileMode.innerHTML
            }
            break;
    }
    displayProfile(opts);
}

if (elUtilWKD) {
    elUtilWKD.onsubmit = function (evt) {
        evt.preventDefault();
    }

    const elInput = document.body.querySelector("#input");
    const elOutput = document.body.querySelector("#output");
    const elOutputDirect = document.body.querySelector("#output_url_direct");
    const elOutputAdvanced = document.body.querySelector("#output_url_advanced");
    let match;

    elInput.addEventListener("input", async function(evt) {
        if (evt.target.value) {
            if (/(.*)@(.{1,}\..{1,})/.test(evt.target.value)) {
                match = evt.target.value.match(/(.*)@(.*)/);
                elOutput.innerText = await computeWKDLocalPart(match[1]);
                elOutputDirect.innerText = `https://${match[2]}/.well-known/openpgpkey/hu/${elOutput.innerText}?l=${match[1]}`;
                elOutputAdvanced.innerText = `https://openpgpkey.${match[2]}/.well-known/openpgpkey/${match[2]}/hu/${elOutput.innerText}?l=${match[1]}`;
            } else {
                elOutput.innerText = await computeWKDLocalPart(evt.target.value);
                elOutputDirect.innerText = "Waiting for input";
                elOutputAdvanced.innerText = "Waiting for input";
            }
        } else {
            elOutput.innerText = "Waiting for input";
            elOutputDirect.innerText = "Waiting for input";
            elOutputAdvanced.innerText = "Waiting for input";
        }
    });

    elInput.dispatchEvent(new Event("input"));
}

if (elUtilQRFP) {
    elUtilQRFP.onsubmit = function (evt) {
        evt.preventDefault();
    }

    const qrTarget = document.getElementById('qrcode');
    const qrContext = qrTarget.getContext('2d');
    const qrOpts = {
        errorCorrectionLevel: 'H',
        margin: 1,
        width: 256,
        height: 256
    };

    const elInput = document.body.querySelector("#input");

    elInput.addEventListener("input", async function(evt) {
        if (evt.target.value) {
            QRCode.toCanvas(qrTarget, evt.target.value, qrOpts, function (error) {
                if (error) {
                    qrContext.clearRect(0, 0, qrTarget.width, qrTarget.height);
                    console.error(error);
                }
            });
        } else {
            qrContext.clearRect(0, 0, qrTarget.width, qrTarget.height);
        }
    });

    elInput.dispatchEvent(new Event("input"));
}

if (elUtilQR) {
    elUtilQR.onsubmit = function (evt) {
        evt.preventDefault();
    }

    const qrTarget = document.getElementById('qrcode');
    const qrContext = qrTarget.getContext('2d');
    const qrOpts = {
        errorCorrectionLevel: 'L',
        margin: 1,
        width: 256,
        height: 256
    };

    const elInput = document.body.querySelector("#input");

    if (elInput.innerText) {
        elInput.innerText = decodeURIComponent(elInput.innerText);

        QRCode.toCanvas(qrTarget, elInput.innerText, qrOpts, function (error) {
            if (error) {
                document.body.querySelector("#qrcode--altLink").href = "#";
                qrContext.clearRect(0, 0, qrTarget.width, qrTarget.height);
                console.error(error);
            } else {
                document.body.querySelector("#qrcode--altLink").href = elInput.innerText;
            }
        });
    } else {
        qrContext.clearRect(0, 0, qrTarget.width, qrTarget.height);
    }
}

if (elUtilProfileURL) {
    elUtilProfileURL.onsubmit = function (evt) {
        evt.preventDefault();
    }

    const elInput = document.body.querySelector("#input"),
        elSource = document.body.querySelector("#source"),
        elOutput = document.body.querySelector("#output");

    let data = {
        input: elInput.value,
        source: elSource.value
    };

    elInput.addEventListener("input", async function(evt) {
        data = {
            input: elInput.value,
            source: elSource.value
        };
        elOutput.innerText = await generateProfileURL(data);
    });

    elSource.addEventListener("input", async function(evt) {
        data = {
            input: elInput.value,
            source: elSource.value
        };
        elOutput.innerText = await generateProfileURL(data);
    });

    elInput.dispatchEvent(new Event("input"));
}
