const openssl = require('../openssl');

/**
 * get public key from private key : openssl pkey -in ecdsa-private.pem  -pubout -outform PEM
 * @param {Buffer|string} private_key Buffer instance of, or full path to private key PEM file
 * @returns {Promise<Buffer>}
 */
async function get_public_key(private_key) {
    if ( 'private_key' in private_key ) {
        private_key = private_key.private_key;
    }
    //  openssl pkey -in ecdsa-private.pem  -pubout -outform PEM
    const {public_key} = await openssl('x509' , {
        pkey : true ,
        in : private_key ,
        pubout : true ,
        outform : 'PEM' ,
        out : {public_key : Buffer} ,
    });
    return public_key;
}

module.exports = get_public_key;
