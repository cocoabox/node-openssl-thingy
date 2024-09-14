const create_conf_data = require('../create-conf-data');

/**
 *
 * @param ext
 * @param serial
 * @param database
 * @param crlnumber
 * @param new_certs_dir
 * @param options
 * @returns {{conf: (Buffer|string)}}
 */
function create_conf_data_for_ca_operations(ext , serial , database , crlnumber , new_certs_dir , options = {}) {
    if ( typeof ext === 'object' && ext?.hasOwnProperty('ext') ) {
        options = {...options , ...ext};
        new_certs_dir = ext.new_certs_dir;
        crlnumber = ext.crlnumber;
        database = ext.database;
        serial = ext.serial;
        ext = ext.ext;
    }
    const {
        out_buffer = true ,
        default_md = 'sha256' ,
    } = options;

    const x509_extensions = {client : 'v3_client' , ca : 'v3_ca' , server : 'v3_server'}[ext];

    const sections = {
        ca : {
            default_ca : 'my_ca' ,
        } ,
        my_ca : Object.assign({} ,
            {
                serial ,
                database ,
                crlnumber ,
                new_certs_dir ,
                default_md ,
                policy : 'policy_match' ,
            } ,
            x509_extensions ? {x509_extensions} : {}
        ) ,
        policy_match : {
            countryName : 'supplied' ,
            stateOrProvinceName : 'optional' ,
            localityName : 'optional' ,
            organizationName : 'optional' ,
            organizationalUnitName : 'optional' ,
            commonName : 'supplied' ,
            emailAddress : 'optional' ,
        } ,
        v3_ca : {
            // extension attributes to use when signing CA certs
            basicConstraints : ['critical' , 'CA:TRUE'] ,
            keyUsage : ['critical' , 'digitalSignature' , 'keyCertSign' , 'cRLSign'] ,
            subjectKeyIdentifier : 'hash' ,
            authorityKeyIdentifier : ['keyid' , 'issuer'] ,
            // crlDistributionPoints: http://XXXX
        } ,
        v3_client : {
            // extension attributes to use when signing CLIENT certs
            basicConstraints : 'CA:FALSE' ,
            nsCertType : ['client' , 'email'] ,
            keyUsage : ['critical' , 'nonRepudiation' , 'digitalSignature' , 'keyEncipherment'] ,
            extendedKeyUsage : ['clientAuth' , 'emailProtection'] ,
            // common
            subjectKeyIdentifier : 'hash' ,
            authorityKeyIdentifier : ['keyid' , 'issuer'] ,
        } ,
        v3_server : {
            // extension attributes to use when signing SERVERF certs
            basicConstraints : 'CA:FALSE' ,
            nsCertType : 'server' ,
            keyUsage : ['critical' , 'digitalSignature' , 'keyEncipherment'] ,
            extendedKeyUsage : 'serverAuth' ,
            // common
            subjectKeyIdentifier : 'hash' ,
            authorityKeyIdentifier : ['keyid' , 'issuer'] ,
        }
    };
    return {
        conf : create_conf_data(sections , {out_buffer}) ,
    };
}

module.exports = create_conf_data_for_ca_operations;
