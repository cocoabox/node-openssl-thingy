const openssl = require('../openssl');

// openssl x509 -in certificate.pem -outform der -out certificate.der
// openssl rsa -in privatekey.pem -outform der -out privatekey.der
async function export_cert_as_der(cert) {
    if ( arguments?.[0].cert ) {
        cert = arguments[0].cert;
    }
    // openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca-cert.pem
    const {out_der} = await openssl('x509' , {
        in : cert ,
        outform : 'DER' ,
        out : {out_der : Buffer} ,
    });
    return out_der;
}

module.exports = export_cert_as_der;
