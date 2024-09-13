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
 * @returns {Promise<Buffer>} resolves with a Buffer to the signed certificate if succeed
 */
async function revoke_cert(
    cert_to_revoke ,
    ca_config ,
    ca_cert ,
    ca_private_key ,
    {ca_private_key_password} = {} ,
) {
    if ( arguments?.[0].cert_to_revoke ) {
        ca_private_key_password = arguments[0].ca_private_key_password;
        ca_private_key = arguments[0].ca_private_key;
        ca_cert = arguments[0].ca_cert;
        ca_config = arguments[0].ca_config;
        cert_to_revoke = arguments[0].cert_to_revoke;
    }
    await openssl('ca' , Object.assign({} , {
            revoke : cert_to_revoke ,
            config : ensure_conf(ca_config) ,
            cert : ca_cert ,
            keyfile : ca_private_key ,
        } ,
        ca_private_key_password ? {passin : `pass:${ca_private_key_password}`} : {} ,
    ));
    return true;
}


module.exports = revoke_cert;
