var app = new Vue({
    el: '#app',
    data: {
        notifications: [],
        mode: 'hkp',
        input: null,
        keyData: null,
        userMail: null,
        fingerprint: null
    },
    mounted: async function() {
        let elProfileUid = document.body.querySelector("#profileUid"),
            elProfileMode = document.body.querySelector("#profileMode");
	
        this.input = elProfileUid.innerHTML;

        let opts = {
            mode: elProfileMode.innerHTML,
            input: elProfileUid.innerHTML,
            server: null,
        };

        let keyData = [];
        try {
            // Get key data
            keyData = await fetchKeys(opts);
        } catch (e) {
            console.error(e);
        }

        this.keyData = keyData

        let userData = keyData.user.user.userId;
        let userName = userData.name ? userData.name : userData.email;
        let userMail = userData.email ? userData.email : null;

        this.userMail = userMail
        this.fingerprint = keyData.fingerprint
        
        document.body.querySelector('#app').style.display = 'block';
	    
	document.body.querySelector('#profileName').innerHTML = userName;
        document.body.querySelector('#profileAvatar').style = "";
        const profileHash = openpgp.util.str_to_hex(openpgp.util.Uint8Array_to_str(await openpgp.crypto.hash.md5(openpgp.util.str_to_Uint8Array(userData.email))));
        document.body.querySelector('#profileAvatar').src = `https://www.gravatar.com/avatar/${profileHash}?s=128&d=mm`;
        document.title = `${userName} - Keyoxide`;

        let notifications = [];
        let notationsRaw = [];
        for (var i = 0; i < keyData.publicKey.users.length; i++) {
            notationsRaw = notationsRaw.concat(keyData.publicKey.users[i].selfCertifications[0].notations);
        }

        for(var i = 0; i < notationsRaw.length; i++) {
            var item = notationsRaw[i]    
            if (item[0] == "proof@metacode.biz") {
                let notification = await verifyProof(item[1], keyData.fingerprint)
                if (notification.type != null) {
                    notifications.push(notification);
                }
            }
        }
    
        notifications.sort((a,b) => (a.type > b.type) ? 1 : ((a.type < b.type) ? -1 : 0));

        this.notifications = notifications
    }
})
