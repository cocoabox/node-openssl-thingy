const create_conf_data = require('../create-conf-data');
const {get_subject} = require('../utils');

function create_conf_data_for_digital_signature(common_name , {
    country ,
    state ,
    city ,
    organization_name ,
    organization_unit ,
    alt_names ,
    out_buffer
} = {}) {
    if ( arguments?.[0].common_name ) {
        out_buffer = arguments[0].out_buffer;
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
            x509_extensions : 'v3_code_signing' ,
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
        v3_code_signing : {
            keyUsage : ['digitalSignature'] ,
            extendedKeyUsage : '1.3.6.1.5.5.7.3.3' ,
        } ,
    };
    return {
        conf : create_conf_data(sections , {out_buffer}) ,
        name : common_name ,
        subject : get_subject(sections , 'req')
    };

}

module.exports = create_conf_data_for_digital_signature;
