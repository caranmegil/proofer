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

router.get('/', async (ctx) => {
    await ctx.render('proofs', { mode: "auto" })
});

router.get('/wkd', async (ctx) => {
    await ctx.render('proofs', { mode: "wkd" })
});
router.get('/wkd/:input', async (ctx) => {
    await ctx.render('proofs', { mode: "wkd", input: ctx.params.input })
});

router.get('/hkp', async (ctx) => {
    await ctx.render('proofs', { mode: "hkp" })
});
router.get('/hkp/:input', async (ctx) => {
    await ctx.render('proofs', { mode: "hkp", input: ctx.params.input })
});

router.get('/plaintext', async (ctx) => {
    await ctx.render('proofs', { mode: "plaintext" })
});

router.get('/keybase', async (ctx) => {
    await ctx.render('proofs', { mode: "keybase" })
});
router.get('/keybase/:username', async (ctx) => {
    await ctx.render('proofs', { mode: "keybase", username: ctx.params.username })
});
router.get('/keybase/:username/:fingerprint', async (ctx) => {
    await ctx.render('proofs', { mode: "keybase", username: ctx.params.username, fingerprint: ctx.params.fingerprint })
});

router.get('/:input', async (ctx) => {
    await ctx.render('proofs', { mode: "auto", input: ctx.params.input })
});

module.exports = router;
