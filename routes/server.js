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
const router = new require('koa-router')();
const proofVerification = require('../server/proofVerification');

router.get('/verify/proxy', async function(ctx) {
    let params = {
        url: ctx.query.url,
        fingerprint: ctx.query.fingerprint,
        checkClaim: ctx.query.checkClaim ? ctx.query.checkClaim : null,
        checkClaimFormat: ctx.query.checkClaimFormat ? ctx.query.checkClaimFormat : "uri",
        checkRelation: ctx.query.checkRelation,
        checkPath: ctx.query.checkPath.split(',')
    }

    try {
        const proofResult = await proofVerification.Proxy(params);
        ctx.status = 200
        ctx.body = proofResult
    } catch (e) {
        console.log(e)
        ctx.status = 400
        ctx.body = { success: false, errors: e };
    }
});

router.get('/verify/twitter', async (ctx) => {
    let params = {
        tweetId: ctx.query.tweetId,
        account: ctx.query.account,
        fingerprint: ctx.query.fingerprint
    }

    try {
        const proofResult = await proofVerification.Twitter(params);
        ctx.status = 200
        ctx.body = proofResult
    } catch (e) {
        console.log(e)
        ctx.status = 400
        ctx.body = { success: false, errors: e };
    }
});

router.get('/verify/lemmynet', async (ctx)=> {
    let params = {
        url: ctx.query.url,
        fingerprint: ctx.query.fingerprint
    }

    try {
        const proofResult = await proofVerification.LemmyNet(params);
        ctx.status = 200
        ctx.body = proofResult
    } catch (e) {
        console.log(e)
        ctx.status = 400
        ctx.body = { success: false, errors: e };
    }
})

router.get('/verify/pixelfed', async (ctx)=> {
    let params = {
        url: ctx.query.url,
        fingerprint: ctx.query.fingerprint
    }

    try {
        const proofResult = await proofVerification.Pixelfed(params);
        ctx.status = 200
        ctx.body = proofResult
    } catch (e) {
        console.log(e)
        ctx.status = 400
        ctx.body = { success: false, errors: e };
    }
})

router.get('/verify/instagram', async (ctx)=> {
    let params = {
        url: ctx.query.url,
        fingerprint: ctx.query.fingerprint
    }
    
    try {
        const proofResult = await proofVerification.Instagram(params);
        ctx.status = 200
        ctx.body = proofResult
    } catch (e) {
        console.log(e)
        ctx.status = 400
        ctx.body = { success: false, errors: e };
    }
})

module.exports = router;
