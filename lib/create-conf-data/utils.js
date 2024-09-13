const querystring = require('node:querystring');
const create_conf_data = require('./create-conf-data');

function ensure_conf(conf) {
    if ( typeof conf === 'string' && fs.existsSync(conf) ) {
        return conf;
    } else if ( Buffer.isBuffer(conf) ) {
        return conf;
    } else if ( typeof conf === 'object' ) {
        return Buffer.from(create_conf_data({sections : conf , out_buffer : true}));
    } else {
        throw new Error(`invalid config; expecting path to physical file or Buffer or dict object but got instead : ${conf}`);
    }
}


function obj2subject(obj) {
    function my_esc(str) {
        return querystring.escape(str)
            .replace(/%40/g , '@')
            .replace(/%20/g , ' ');
    }

    return Object.entries(obj)
        .map(([key , value]) => `${key}=${my_esc(value)}`)
        .join('/');
}

function subject2obj(subject) {
    if ( subject.startsWith('/') ) subject = subject.substring(1);

    return subject.split('/').map(a => a.trim()).filter(a => !! a)
        .reduce((acc , part) => {
            const [key , value] = part.split('=');
            if ( key && value ) acc[key] = querystring.unescape(value);
            return acc;
        } , {});
}


function get_subject(conf , main_section_name) {
    const main_section = conf[main_section_name];
    const dn_section_name = main_section.distinguished_name;
    const dn_section = conf[dn_section_name];

    const subjectString = obj2subject(dn_section);
    return `/${subjectString}`;
}

module.exports = {ensure_conf , get_subject , obj2subject , subject2obj};
