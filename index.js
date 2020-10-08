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
x
You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary. For
more information on this, and how to apply and follow the GNU AGPL, see <https://www.gnu.org/licenses/>.
*/
const Koa = require('koa');
const fs = require('fs');
const mount = require('koa-mount')
const app = new Koa();
const koaPug = require('koa-pug');
const serve = require('koa-static')

const env = {};
// const { stringReplace } = require('string-replace-middleware');
const validator = require('koa-validator')
require('dotenv').config();

let packageData = JSON.parse(fs.readFileSync('package.json'));

const pug = new koaPug({
    app: app,
    viewPath: __dirname + '/views',
    locals: {
        settings: {
            'env': process.env.NODE_ENV || "production",
            'port': process.env.PORT || 3000,
            'domain': process.env.DOMAIN || "keyoxide.org",
            'keyoxide_version': packageData.version,
            'onion_url': process.env.ONION_URL
        }
    }
})
app.context.env = process.env.NODE_ENV || "production";
app.context.port = process.env.PORT || 3000;
app.context.domain = process.env.DOMAIN || "keyoxide.org";
app.context.keyoxide_version = packageData.version;
app.context.onion_url = process.env.ONION_URL;

// app.use(stringReplace({
    // PLACEHOLDER__XMPP_VCARD_SERVER_DOMAIN: process.env.XMPP_VCARD_SERVER_DOMAIN || 'xmpp-vcard.keyoxide.org'
// }, {
    // contentTypeFilterRegexp: /application\/javascript/,
// }));

app.use(mount('/static', serve(__dirname + '/static/')));

app.use(mount('/', require('./routes/main').middleware()));
app.use(mount('/static', require('./routes/static').middleware()));
app.use(mount('/server', require('./routes/server').middleware()));
app.use(mount('/encrypt', require('./routes/encrypt').routes()));
app.use(mount('/verify', require('./routes/verify').middleware()));
app.use(mount('/proofs', require('./routes/proofs').middleware()));
app.use(mount('/util', require('./routes/util').middleware()));
app.use(mount('/', require('./routes/profile').middleware()));

app.listen(app.context.port, () => {
    console.log(`Node server listening at http://localhost:${app.context.port}`);
});
