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
const bent = require('bent');
const getJSON = bent('json');
require('dotenv').config();

const Proxy = async (params) => {
    let res = {
        success: false,
        errors: [],
        isVerified: false,
        params: params
    }

    if (!res.params.checkClaim) {
        switch (res.params.checkClaimFormat) {
            default:
            case "uri":
                res.params.checkClaim = `openpgp4fpr:${res.params.fingerprint}`;
                break;
            case "message":
                res.params.checkClaim = `[Verifying my OpenPGP key: openpgp4fpr:${res.params.fingerprint}]`;
                break;
            case "fingerprint":
                res.params.checkClaim = res.params.fingerprint;
                break;
        }
    }

    const obj = await getJSON(res.params.url);
    res.isVerified = VerifyJsonProof(obj, res.params.checkPath, res.params.checkClaim, res.params.checkRelation);
    res.success = true;

    return res;
};

const Twitter = async (params) => {
    let res = {
        success: false,
        errors: [],
        isVerified: false,
        params: params
    }

    let twitter_api_auth = process.env.TWITTER_API_AUTH;
    if (!twitter_api_auth) {
        let proofUrl = `https://mobile.twitter.com/${res.params.account}/status/${res.params.tweetId}`;
        let re = new RegExp(`[Verifying my OpenPGP key: openpgp4fpr:${res.params.fingerprint}]`, "gi");
        const get = bent('GET');
        const obj = await get(proofUrl);
        res.isVerified = re.test(obj.data);
        return res;
    }

    let proofUrl = `https://api.twitter.com/labs/2/tweets/${res.params.tweetId}?tweet.fields=author_id,created_at,id,source,text`;
    let re = new RegExp(`[Verifying my OpenPGP key: openpgp4fpr:${res.params.fingerprint}]`, "gi");

    const get = bent('GET', 'json', {'Content-Type': 'application/json', 'Authorization': `Bearer ${twitter_api_auth}`});
    const obj = await get(proofUrl);
    res.isVerified = re.test(obj.data.text);
    res.success = true;

    return res;
};

const LemmyNet = async (params) => {
    let res = {
        success: false,
        errors: [],
        isVerified: false,
        params: params
    }

    let proofUrl = res.params.url
    let proofRE = new RegExp(`\\[Verifying my OpenPGP key: openpgp4fpr\\:${res.params.fingerprint}\\]`, "gi");
    const get = bent('GET', 'string')
    const obj = await get(proofUrl);

    let match = obj.match(/\<script\>window.isoData = (\{.+\})\<\/script\>/)
    
    if (match != null) {
        const json = JSON.parse(match[1])
        const routeData = json.routeData
        for( let routeDataI=0; routeDataI < routeData.length; routeDataI++) {
            if (routeData[routeDataI].user) {
                if (routeData[routeDataI].user.bio) {
                    res.isVerified = proofRE.test(routeData[routeDataI].user.bio)
                }
                break;
            }
        }
    }

    return res
}

const Instagram = async (params) => {
    let res = {
        success: false,
        errors: [],
        isVerified: false,
        params: params
    }

    let proofUrl = res.params.url
    let proofRE = new RegExp(`\\[Verifying my OpenPGP key: openpgp4fpr\\:${res.params.fingerprint}\\]`, "gi");
    const get = bent('GET', 'string')
    const obj = await get(proofUrl);
    
    let match = obj.match(/\<script type=\"text\/javascript\"\>\s*window._sharedData = ({.+});\s*\<\/script\>/is)

    if (match != null) {
        const json = JSON.parse(match[1])
        for( let itemI = 0; itemI < json.entry_data.ProfilePage.length; itemI++) {
            let item = json.entry_data.ProfilePage[itemI]
            if (item.graphql && item.graphql.user) {
                res.isVerified = proofRE.test(item.graphql.user.biography)
                break;
            }

        }
    }

    return res
}

const Pixelfed = async (params) => {
    let res = {
        success: false,
        errors: [],
        isVerified: false,
        params: params
    }

    let proofUrl = res.params.url
    let proofRE = new RegExp(`\\[Verifying my OpenPGP key: openpgp4fpr\\:${res.params.fingerprint}\\]`, "gi");
    const get = bent('GET', 'string')
    const obj = await get(proofUrl);

    let match = obj.match(/\<meta property=\"og\:description\" content=\"(.*)\"\>/si)

    if (match != null) {
        const description = match[1]
        res.isVerified = proofRE.test(description)
    }

    return res
}

const VerifyJsonProof = (data, checkPath, checkClaim, checkRelation) => {
    let isVerified = false;
    let re;

    if (!data) {
        return isVerified;
    }

    if (checkPath.length == 0) {
        switch (checkRelation) {
            default:
            case 'contains':
                re = new RegExp(checkClaim, "gi");
                return re.test(data);
                break;
            case 'eq':
                return data.replace(/\r?\n|\r/, '').toLowerCase() == checkClaim.toLowerCase();
                break;
            case 'oneOf':
                re = new RegExp(checkClaim, "gi");
                return re.test(data.join("|"));
                break;
        }
    }

    if (Array.isArray(data)) {
        data.forEach((item, i) => {
            isVerified = isVerified || VerifyJsonProof(item, checkPath, checkClaim, checkRelation);
        });
    } else if (Array.isArray(data[checkPath[0]])) {
        data[checkPath[0]].forEach((item, i) => {
            isVerified = isVerified || VerifyJsonProof(item, checkPath.slice(1), checkClaim, checkRelation);
        });
    } else {
        isVerified = isVerified || VerifyJsonProof(data[checkPath[0]], checkPath.slice(1), checkClaim, checkRelation);
    }

    return isVerified;
}

exports.Proxy = Proxy;
exports.Twitter = Twitter;
exports.LemmyNet = LemmyNet
exports.Pixelfed = Pixelfed
exports.Instagram = Instagram