const openssl = require('../openssl');

// openssl pkcs12 -export -inkey private_key.pem -in certificate.pem -out keypair.p12 -nodes
async function export_pkcs12(cert , private_key , export_password , {legacy} = {}) {
    if ( arguments?.[0].private_key ) {
        legacy = arguments[0].legacy;
        export_password = arguments[0].export_password;
        private_key = arguments[0].private_key;
        cert = arguments[0].cert;
    }
    if ( ! export_password ) {
        throw new Error('export_password cannot be empty');
    }
    try {
        // openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca-cert.pem
        const {out_pkcs12} = await openssl('pkcs12' , {
            legacy : !! legacy ,
            export : true ,
            inkey : private_key ,
            nodes : true ,
            in : cert ,
            out : {out_pkcs12 : Buffer} ,
            passout : `pass:${export_password}` ,
        });
        return out_pkcs12;
    } catch (err) {
        console.warn('failed to export PKCS12' , err);
        throw err;
    }
}

module.exports = export_pkcs12;
