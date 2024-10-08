const openssl = require('./openssl');

openssl.create_rsa_keypair = require('./utils/create-rsa-keypair');
openssl.create_ecdsa_keypair = require('./utils/create-ecdsa-keypair');
openssl.create_cert = require('./utils/create-cert');
openssl.create_csr = require('./utils/create-csr');
openssl.get_public_key = require('./utils/get-public-key');
openssl.sign_csr = require('./utils/sign-csr');

openssl.export_pkcs12 = require('./utils/export-pkcs12');
openssl.export_key_as_der = require('./utils/export-key-as-der');
openssl.export_cert_as_der = require('./utils/export-cert-as-der');

openssl.revoke_cert = require('./utils/revoke-cert');
openssl.get_crl = require('./utils/get-crl');
openssl.inspect_crl = require('./utils/inspect-crl');
openssl.verify_crl = require('./utils/verify-crl');

openssl.sign_data = require('./utils/sign-data');
openssl.verify_signature = require('./utils/verify-signature');

module.exports = openssl;
