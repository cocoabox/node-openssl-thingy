const create_conf_data = require('../create-conf-data');

/**
 *
 * @param {string} serial       full path to the SERIAL-NUMBER file
 * @param {string} database     full path to the INDEX file
 * @param {string} crlnumber    full path to CRL-NUMBER file
 * @param {string} new_certs_dir
 * @param {string?} default_md
 * @param {object?} policy_match
 * @param {boolean?} out_buffer
 * @returns {{name:string, conf: (Buffer|string)}}
 */
function create_conf_data_for_ca_operations(serial , database , crlnumber , new_certs_dir , {
    default_md ,
    policy_match ,
    out_buffer
} = {}) {
    if ( arguments?.[0].serial ) {
        out_buffer = arguments[0].out_buffer;
        default_md = arguments[0].default_md;
        crlnumber = arguments[0].crlnumber;
        new_certs_dir = arguments[0].new_certs_dir;
        database = arguments[0].database;
        serial = arguments[0].serial;
    }
    default_md = default_md ?? 'sha256';
    serial = serial ?? 'serial';
    database = database ?? 'database';
    new_certs_dir = new_certs_dir ?? 'new_certs_dir';

    const sections = {
        ca : {
            default_ca : 'my_ca' ,
        } ,
        my_ca : {
            serial ,
            database ,
            crlnumber ,
            new_certs_dir ,
            default_md ,
            policy : 'policy_match' ,
            x509_extensions : 'v3_ca' ,
        } ,
        policy_match : Object.assign({} ,
            {commonName : 'supplied' ,} ,
            policy_match && typeof policy_match === 'object' ? policy_match : {} ,
        ) ,
        v3_ca : {
            basicConstraints : ['critical' , 'CA:TRUE'] ,
            keyUsage : ['critical' , 'keyCertSign' , 'cRLSign'] ,
            subjectKeyIdentifier : 'hash' ,
            authorityKeyIdentifier : ['keyid:always' , 'issuer'] ,
        }
    };
    return {conf : create_conf_data(sections , {out_buffer})};
}

module.exports = create_conf_data_for_ca_operations;
