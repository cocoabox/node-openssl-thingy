const openssl = require('../openssl');

/**
 * creates an RSA keypair and return the Buffer objects of the public and private keys in PEM format
 * @param {number?} [bits=4096]
 * @param {string?} password
 * @returns {Promise<{public_key:Buffer, password?:string, private_key:Buffer}>}
 */
async function create_rsa_keypair({bits = 4096 , password} = {}) {
    const {private_key} = await openssl('genpkey' , Object.assign({} , {
            algorithm : 'RSA' ,
            out : {private_key : Buffer} ,
            pkeyopt : `rsa_keygen_bits:${bits}` ,
            outform : 'PEM' ,
        } ,
        password ? {aes256 : true , pass : `pass:${password}`} : {} ,
    ));
    const {public_key} = await openssl('rsa' , Object.assign({} , {
            pubout : true ,
            in : private_key ,
            out : {public_key : Buffer} ,
        } ,
        password ? {passin : `pass:${password}`} : {} ,
    ));
    return {private_key , public_key , password};
}

module.exports = create_rsa_keypair;
