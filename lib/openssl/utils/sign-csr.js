const openssl = require('../openssl');
const {ensure_conf} = require('../../create-conf-data');


/**
 * sign a CSR file using a CA cert and private key;
 * openssl will update the ca_config.serial and ca_config.database files on disk, and create
 * a new {SERIAL}.pem inside ca_config.new_certs_dir directory; you are responsible for provindg these files/dirs
 * beforehand, and afterwards, clean them up
 *
 * @param {string|Buffer} csr full path to CSR file, or content of CSR file
 * @param {string|Buffer} ca_config full path to a CA Config file, or content of that;
 *      to generate, call create_conf_data.for_ca_operations()
 *      note that the serial, database, and new_cert_dir elements must exist on disk
 * @param {string|Buffer} ca_cert full path to CA cert PEM file or content of such
 * @param {string|Buffer} ca_private_key full path to CA private key PEM file or content of such
 * @param {string?} ca_private_key_password if CA private key is password protected, provide it here
 * @param {number?} [days=9999]
 * @returns {Promise<Buffer>} resolves with a Buffer to the signed certificate if succeed
 */
async function sign_csr(
    csr ,
    ca_config ,
    ca_cert ,
    ca_private_key ,
    {ca_private_key_password , days} = {} ,
) {
    if ( arguments?.[0].csr ) {
        days = arguments[0].days;
        ca_private_key_password = arguments[0].ca_private_key_password;
        ca_private_key = arguments[0].ca_private_key;
        ca_cert = arguments[0].ca_cert;
        ca_config = arguments[0].ca_config;
        csr = arguments[0].csr;
    }
    days = days ?? 9999;
    const {cert} = await openssl('ca' , Object.assign({} , {
            config : ensure_conf(ca_config) ,
            cert : ca_cert ,
            keyfile : ca_private_key ,
            in : csr ,
            out : {cert : Buffer} , // promise will resolve as {cert:BUFFER_OBJECT, ...}
            days ,
            batch : true ,
        } ,
        ca_private_key_password ? {passin : `pass:${ca_private_key_password}`} : {} ,
    ));
    return cert;
}


module.exports = sign_csr;
