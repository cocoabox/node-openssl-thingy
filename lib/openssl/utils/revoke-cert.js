const openssl = require('../openssl');
const {ensure_conf} = require('../../create-conf-data');


/**
 *
 * @param {string|Buffer} cert_to_revoke full path to cert file, or content of cert file to revoke
 * @param {string|Buffer} ca_config full path to a CA Config file, or content of that;
 *      to generate, call create_conf_data.for_ca_operations()
 *      note that the serial, database, and new_cert_dir elements must exist on disk
 * @param {string|Buffer} ca_cert full path to CA cert PEM file or content of such
 * @param {string|Buffer} ca_private_key full path to CA private key PEM file or content of such
 * @param {string?} ca_private_key_password if CA private key is password protected, provide it here
 * @param {string?} reason
 * @returns {Promise<Buffer>} resolves with a Buffer to the signed certificate if succeed
 */
async function revoke_cert(
    cert_to_revoke ,
    ca_config ,
    ca_cert ,
    ca_private_key ,
    {ca_private_key_password , reason} = {} ,
) {
    const valid_reasons = ['unspecified' , 'keyCompromise' , 'CACompromise' , 'affiliationChanged' , 'superseded' , 'cessationOfOperation' , 'certificateHold' , 'removeFromCRL'];
    if ( typeof cert_to_revoke === 'object' && cert_to_revoke.hasOwnProperty('cert_to_revoke') ) {
        reason = cert_to_revoke.reason;
        ca_private_key_password = cert_to_revoke.ca_private_key_password;
        ca_private_key = cert_to_revoke.ca_private_key;
        ca_cert = cert_to_revoke.ca_cert;
        ca_config = cert_to_revoke.ca_config;
        cert_to_revoke = cert_to_revoke.cert_to_revoke;
    }
    if ( reason && ! valid_reasons.includes(reason) )
        throw new Error(`invalid reason; expecting ${valid_reasons.join(',')} but got "${reason}"`);
    await openssl('ca' , Object.assign({} , {
            revoke : cert_to_revoke ,
            config : ensure_conf(ca_config) ,
            cert : ca_cert ,
            keyfile : ca_private_key ,
        } ,
        ca_private_key_password ? {passin : `pass:${ca_private_key_password}`} : {} ,
        reason ? {crl_reason : reason} : {} ,
    ));
    return true;
}


module.exports = revoke_cert;
