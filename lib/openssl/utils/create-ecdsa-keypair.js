const openssl = require('../openssl');

/**
 * create ECDSA key pair using p256 or p384 elliptic curve
 * @param {string} [mode="p256"]
 * @param {string?} password
 * @returns {Promise<{public_key:Buffer, password?:string, private_key:Buffer}>}
 */
async function create_ecdsa_keypair({mode = 'p256' , password} = {}) {
    const name = {
        p256 : 'prime256v1' ,
        p384 : 'secp384r1' ,
        'p-256' : 'prime256v1' ,
        'p-384' : 'secp384r1' ,
    }[mode.toLowerCase()];
    if ( ! name ) throw RangeError(`invalid value of mode ; expecting "p256" or "p384"`);

    const {private_key} = await openssl('ecparam' , Object.assign({} , {
            name ,
            genkey : true ,
            out : {private_key : Buffer} ,
            outform : 'PEM' ,
        } ,
        password ? {aes256 : true , pass : `pass:${password}`} : {} ,
    ));
    const {public_key} = await openssl('ec' , Object.assign({} , {
            pubout : true ,
            in : private_key ,
            out : {public_key : Buffer} ,
            outform : 'PEM' ,
        } ,
        password ? {passin : `pass:${password}`} : {} ,
    ));
    return {private_key , public_key , password};
}

module.exports = create_ecdsa_keypair;
