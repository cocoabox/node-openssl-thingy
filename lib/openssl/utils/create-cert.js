const openssl = require('../openssl');
const {ensure_conf} = require('../../create-conf-data');

async function create_cert(private_key , conf , {days} = {}) {
    if ( arguments?.[0].private_key ) {
        days = arguments[0].days;
        conf = arguments[0].conf;
        private_key = arguments[0].private_key;
    }
    days = days ?? 9999;
    const config = ensure_conf(conf);
    // openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 3650 -out ca-cert.pem
    const {cert} = await openssl('req' , {
        x509 : true ,
        new : true ,
        nodes : true ,
        key : private_key ,
        sha256 : true ,
        days ,
        config ,
        out : {cert : Buffer} ,
    });
    return cert;
}

module.exports = create_cert;
