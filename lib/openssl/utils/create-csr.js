const openssl = require('../openssl');
const {ensure_conf} = require('../../create-conf-data');


/**
 * creates a CSR file for a server
 * @param {Buffer|string} private_key Buffer to the server's private key file, or full path to that file on disk
 * @param {Buffer|string} conf a config file Buffer produced by create_conf_data.for_server() ; or full path to your own config file on disk
 * @returns {Promise<Buffer>}
 */
async function create_csr(private_key , conf) {
    if ( typeof private_key === 'object' && private_key?.hasOwnProperty('private_key') ) {
        conf = private_key.conf;
        private_key = private_key.private_key;
    }
    const config = ensure_conf(conf);
    // openssl req -new -key intermediate-key.pem -out intermediate.csr -config intermediate-csr.conf
    const {csr} = await openssl('req' , {
        new : true ,
        key : private_key ,
        config ,
        out : {csr : Buffer} ,
    });
    return csr;
}


module.exports = create_csr;
