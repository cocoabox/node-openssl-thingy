const create_conf_data = require('../create-conf-data');
const {get_subject} = require('../utils');

/**
 *
 * @param {string} common_name  first and last name of the client
 * @param {string|string[]} email   provide at least one email address for this client
 * @param {object} options
 * @param {string?} options.country
 * @param {string?} options.state
 * @param {string?} options.city
 * @param {string?} options.organization_name
 * @param {string?} options.organization_unit
 * @param {boolean?} [options.out_buffer=true]  if true then the .conf element returned will be a Buffer instance, else a string
 * @returns {{subject: string, name: (string|*), conf: (Buffer|string)}}
 */
function create_conf_data_for_client(common_name , email , options = {}) {
    if ( typeof common_name === 'object' && common_name?.hasOwnProperty('common_name') ) {
        options = {...options , ...common_name};
        email = common_name.email;
        common_name = common_name.common_name;
    }
    const {
        country = 'US' ,
        state = 'WA' ,
        city = 'Seattle' ,
        organization_name = 'Contoso Corporation' ,
        organization_unit = 'Sales Department' ,
        out_buffer = true ,
    } = options;
    if ( ! email || email?.length === 0 ) throw Error('must provide at least 1 email address');
    email = Array.isArray(email) ? email : [email];

    const sections = {
        req : {
            distinguished_name : 'req_distinguished_name' ,
            x509_extensions : 'v3_client_auth' ,
            prompt : 'no' ,
        } ,
        req_distinguished_name : {
            C : country ,
            ST : state ,
            L : city ,
            O : organization_name ,
            OU : organization_unit ,
            CN : common_name ,
            emailAddress : email[0] ,
        } ,
        v3_client_auth : {
            extendedKeyUsage : '1.3.6.1.5.5.7.3.2' , // client authentication
            keyUsage : 'digitalSignature' ,
            subjectAltName : '@alt_names' ,
        } ,
        alt_names : email.reduce((accum , name , index) => {
            accum[`email.${index + 1}`] = name;
            return accum;
        } , {}) ,
    };
    return {
        conf : create_conf_data(sections , {out_buffer}) ,
        name : common_name ,
        subject : get_subject(sections , 'req')
    };

}

module.exports = create_conf_data_for_client;
