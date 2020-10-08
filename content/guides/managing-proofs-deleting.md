# Deleting Proofs using GnuPG

Over time, you may need to delete proofs. Changing proofs can be achieved by deleting proofs and adding new ones.

## Delete all proofs

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Launch the notation prompt:

`notation`

Enter the 'none' notation to delete all notations:

`none`

Save the changes:

`save`

## Delete one of your proofs

First, edit the key (make sure to replace FINGERPRINT):

`gpg --edit-key FINGERPRINT`

Launch the notation prompt:

`notation`

Enter the **-** (minus) symbol followed by the proof you want to delete. Make sure you type the proof exactly like it is in your key.

`-proof@metacode.biz=dns:yourdomain.org?type=TXT`

_To make it easier to enter the right proof, you could first [list all proofs](managing-proofs-listing) and simply copy the proof (including "proof@metacode.biz=") you want to delete._

Save the changes:

`save`

Upload the key to WKD or use the following command to upload the key to [keys.openpgp.org](https://keys.openpgp.org) (make sure to replace FINGERPRINT):

`gpg --keyserver hkps://keys.openpgp.org --send-keys FINGERPRINT`
