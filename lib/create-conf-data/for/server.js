const create_conf_data = require('../create-conf-data');
const {get_subject} = require('../utils');

/**
 * returns conf file data either as a Buffer object or String
 * @param {string|{common_name:string,country:string,city:string,organization_name:string,organization_unit:string,alt_names:string[],out_buffer:boolean}} common_name
 *      pass the required common name property for the server; or a dict containing one or more named elements below {common_name:**, country:**, ...}
 * @param {object} options
 * @param {string?} options.country
 * @param {string?} options.state
 * @param {string?} options.city
 * @param {string?} options.organization_name
 * @param {string?} options.organization_unit
 * @param {string[]?} options.alt_names
 * @param {boolean?} [options.out_buffer=true]  if true then the .conf element returned will be a Buffer instance, else a string
 * @returns {{subject: string, name: string, conf: (Buffer|string)}}
 */
function create_conf_data_for_server(common_name , options = {}) {
    if ( typeof common_name === 'object' && common_name?.hasOwnProperty('common_name') ) {
        options = {...options , ...common_name};
        common_name = common_name.common_name;
    }
    const {
        country = 'US' ,
        state = 'WA' ,
        city = 'Seattle' ,
        organization_name = 'Contoso Corporation' ,
        organization_unit = 'Sales Department' ,
        alt_names = [] ,
        out_buffer = true
    } = options;

    const sections = {
        req : {
            distinguished_name : 'req_distinguished_name' ,
            x509_extensions : 'v3_server_auth' ,
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
        v3_server_auth : {
            extendedKeyUsage : '1.3.6.1.5.5.7.3.1' ,
            keyUsage : ['digitalSignature' , 'keyEncipherment'] ,
        } ,
    };
    if ( alt_names && Array.isArray(alt_names) ) {
        sections.v3_server_auth.subjectAltName = '@alt_names';
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

module.exports = create_conf_data_for_server;
