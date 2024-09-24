const create_conf_data = require('../create-conf-data');
const {get_subject} = require('../utils');
const default_distinguished_name = require('./default-distinguished-name');
// [req]
// distinguished_name = req_distinguished_name
// x509_extensions = v3_ca
// prompt = no
//
// [req_distinguished_name]
// C = US
// ST = State
// L = City
// O = Organization Name
// OU = Organizational Unit
// CN = Root CA
//
// [v3_ca]
// basicConstraints = critical,CA:TRUE
// keyUsage = critical,keyCertSign,cRLSign
// subjectKeyIdentifier = hash
// authorityKeyIdentifier = keyid:always,issuer
// subjectAltName = @alt_names
//
// [alt_names]
// DNS.1 = example.com
// DNS.2 = *.example.com
// DNS.3 = anotherdomain.com

function create_conf_data_for_ca(common_name , options = {}) {
    if ( typeof common_name === 'object' && common_name?.hasOwnProperty('common_name') ) {
        options = {...options , ...common_name};
        common_name = common_name.common_name;
    }
    if ( ! common_name || typeof common_name !== 'string' )
        throw new Error(`expecting common_name to be non-empty string; got instead : ${common_name}`);
    const {
        country = default_distinguished_name.country ,
        state = default_distinguished_name.state ,
        city = default_distinguished_name.city ,
        organization_name = default_distinguished_name.organization_name ,
        organization_unit = default_distinguished_name.organization_unit ,
        alt_names = [] ,
        out_buffer = true ,
        ocsp_url ,
        crl_url ,
    } = options;
    const sections = {
        req : {
            distinguished_name : 'req_distinguished_name' ,
            x509_extensions : 'v3_ca' ,
            prompt : 'no' ,
        } ,
        req_distinguished_name : {
            C : country ,
            ST : state ,
            L : city ,
            O : organization_name ,
            OU : organization_unit ,
            CN : common_name ,
        } ,
        v3_ca : {
            basicConstraints : ['critical' , 'CA:TRUE'] ,
            keyUsage : ['critical' , 'keyCertSign' , 'cRLSign'] ,
            subjectKeyIdentifier : 'hash' ,
            authorityKeyIdentifier : ['keyid:always' , 'issuer'] ,
        } ,
    };
    if ( crl_url ) {
        sections.v3_ca.crlDistributionPoints = `URI:${crl_url}`;
    }
    if ( ocsp_url ) {
        sections.v3_ca.authorityInfoAccess = `OCSP;URI:${ocsp_url}`;
    }
    if ( alt_names && Array.isArray(alt_names) && alt_names.length > 0 ) {
        sections.v3_ca.subjectAltName = '@alt_names';
        sections.alt_names = alt_names.reduce((accum , name , index) => {
            accum[`DNS.${index + 1}`] = name;
            return accum;
        } , {});
    }
    return {
        conf : create_conf_data(sections , {out_buffer}) ,
        name : common_name ,
        subject : get_subject(sections , 'req')
    };
}

module.exports = create_conf_data_for_ca;
