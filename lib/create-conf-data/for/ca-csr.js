const create_conf_data = require('../create-conf-data');
const {get_subject} = require('../utils');

function create_conf_data_for_ca_csr(common_name , {
    country ,
    state ,
    city ,
    organization_name ,
    organization_unit ,
    alt_names ,
    crl_url ,
    ocsp_url ,
    out_buffer
} = {}) {
    if ( arguments?.[0].common_name ) {
        alt_names = arguments[0].alt_names;
        out_buffer = arguments[0].out_buffer;
        ocsp_url = arguments[0].ocsp_url;
        crl_url = arguments[0].crl_url;
        organization_unit = arguments[0].organization_unit;
        organization_name = arguments[0].organization_name;
        city = arguments[0].city;
        state = arguments[0].state;
        country = arguments[0].country;
        common_name = arguments[0].common_name;
    }
    country = country ?? 'US';
    state = state ?? 'State';
    city = city ?? 'City';
    organization_name = organization_name ?? 'My Organization';
    organization_unit = organization_unit ?? 'My Organization';
    out_buffer = out_buffer ?? true;

    const sections = {
        req : {
            distinguished_name : 'req_distinguished_name' ,
            req_extensions : 'req_ext' ,
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
        req_ext : {
            basicConstraints : ['CA:TRUE'] ,
            keyUsage : ['keyCertSign' , 'cRLSign'] ,
        } ,
    };
    if ( crl_url ) {
        sections.v3_ca.crlDistributionPoints = `URI:${crl_url}`;
    }
    if ( ocsp_url ) {
        sections.v3_ca.authorityInfoAccess = `OCSP;URI:${ocsp_url}`;
    }
    if ( alt_names && Array.isArray(alt_names) ) {
        sections.req_ext.subjectAltName = '@alt_names';
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

module.exports = create_conf_data_for_ca_csr;
