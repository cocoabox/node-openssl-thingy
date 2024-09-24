const openssl = require('../openssl');
const fs = require('node:fs');

/**
 * openssl dgst -verify ../../public-key.pem  -keyform pem  -signature signature.bin    < data-string.txt
 * @param {string|Buffer} public_key
 * @param {string|Buffer} signature
 * @param {string|Buffer} signed_data
 * @returns {Promise<{stdout: *}>}
 */
async function verify_signature(
    public_key ,
    signature ,
    signed_data ,
) {
    if ( 'public_key' in public_key ) {
        signed_data = public_key.signed_data;
        signature = public_key.signature;
        public_key = public_key.public_key;
    }
    signed_data = Buffer.isBuffer(signed_data) ? signed_data : await fs.readFile(signed_data);
    try {
        const {stdout} = await openssl('dgst' ,
            {verify : public_key , keyform : 'pem' , signature , binary : true} ,
            {stdin : signed_data}
        );
        return {stdout};
    } catch ({stderr}) {
        console.warn('signature verification failed :' , stderr);
        return false;
    }
}


module.exports = verify_signature;
