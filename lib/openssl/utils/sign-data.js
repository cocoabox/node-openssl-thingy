const openssl = require('../openssl');
const fs = require('node:fs');

/**
 * openssl dgst -sign ../../private-key.pem  -keyform pem -out sig -binary data-string.txt
 * @param {string|Buffer} private_key Buffer or full path to x509 private key in PEM format
 * @param {string|Buffer} data_to_sign Buffer or full path to file containing data to sign
 * @returns {Promise<{Buffer}>} resolves with Buffer to binary signature
 */
async function sign_data(
    private_key ,
    data_to_sign ,
) {
    if ( 'public_key' in public_key ) {
        data_to_sign = public_key.signed_data;
        signature = public_key.signature;
        public_key = public_key.public_key;
    }
    data_to_sign = Buffer.isBuffer(data_to_sign) ? data_to_sign : await fs.readFile(data_to_sign);
    const {out} = await openssl('dgst' ,
        {sign : private_key , keyform : 'pem' , out : Buffer , binary : true} ,
        {stdin : data_to_sign}
    );
    return out;
}


module.exports = sign_data;
