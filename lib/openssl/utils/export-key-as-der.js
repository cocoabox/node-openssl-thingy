const openssl = require('../openssl');

// openssl x509 -in certificate.pem -outform der -out certificate.der
// openssl rsa -in privatekey.pem -outform der -out privatekey.der
async function export_key_as_der(private_key , {public_key} = {}) {
    if ( arguments?.[0].private_key ) {
        public_key = arguments[0].public_key;
        private_key = arguments[0].private_key;
    }
    // openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca-cert.pem

    const out_private_key = private_key
        ? (await openssl('rsa' , {
            in : private_key ,
            outform : 'DER' ,
            out : Buffer ,
        }))?.out
        : undefined;

    const out_public_key = public_key
        ? (await openssl('rsa' , {
            pubin : public_key ,
            outform : 'DER' ,
            out : Buffer ,
        }))?.out
        : undefined;

    return {public_key : out_public_key , private_key : out_private_key};
}

module.exports = export_key_as_der;
