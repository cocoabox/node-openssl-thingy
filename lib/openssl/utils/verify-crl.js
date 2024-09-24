const openssl = require('../openssl');
const fs = require('node:fs');

/**
 * verify if a cert is revoked by a CA
 * @param {string|Buffer} crl  full path to, or Buffer to content of CRL file issued by the CA
 * @param {string|Buffer} cert full path to, or Buffer to content of certificate to be checked
 * @param {string|Buffer} ca_cert_chain full path to, or Buffer to content of cert chain of the CA
 * @returns {Promise<{stdout: *}>}
 */
async function verify_crl(
    crl ,
    cert ,
    ca_cert_chain
) {
    if ( crl?.crl ) {
        ca_cert_chain = crl.ca_cert_chain;
        cert = crl.cert;
        crl = crl.crl;
    }
    crl = Buffer.isBuffer(crl) ? crl : await fs.readFile(crl);
    ca_cert_chain = Buffer.isBuffer(ca_cert_chain) ? ca_cert_chain : await fs.readFile(ca_cert_chain);
    try {
        const {stdout} = await openssl('verify' ,
            {crl_check : true , CAfile : Buffer.concat([crl , ca_cert_chain])} ,
            {stdin : cert}
        );
        return {stdout};
    } catch ({stdout , stderr}) {
        const [dn , error_line] = stderr.split('\n');
        const [error_line_lhs , error_line_rhs] = (error_line ?? '').split(':').map(l => l.trim());
        throw {error : 'verify-error' , verify_error_reason : error_line_rhs , stderr};
    }
}


module.exports = verify_crl;
