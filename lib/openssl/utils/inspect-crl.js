const openssl = require('../openssl');

/**
 * @param {string} output  openssl crl command stdout output
 * @returns {{next_update:Date,last_update:Date,crl_number:number}}
 */
function parse_crl_output(output) {
    const result = {};
    const lines = output.trim().split('\n').map(str => str.trim()).filter(n => !! n);
    for ( const line of lines ) {
        const match = line.match(/^(.*?)=(.*)$/);
        if ( match ) {
            const lhs = match[1].trim();
            const rhs = match[2].trim();
            const conversions = {
                nextUpdate : value => new Date(value) ,
                lastUpdate : value => new Date(value) ,
                crlNumber : value => parseInt(value , 16) ,
            };
            result[lhs] = lhs in conversions ? conversions[lhs](rhs) : rhs;
        }
    }
    return Object.fromEntries(Object.entries(result).map(([k , v]) => {
        k = {
            nextUpdate : 'next_update' ,
            lastUpdate : 'last_update' ,
            crlNumber : 'crl_number' ,
        }[k] ?? k;
        return [k , v];
    }));
}

/**
 *
 * @param {Buffer} crl
 * @returns {Promise<{next_update: Date, last_update: Date, crl_number: number}>}
 */
async function inspect_crl(crl) {
    if ( arguments?.[0].crl ) {
        crl = arguments[0].crl;
    }
    const {stdout} = await openssl('crl' , {
        in : crl ,
        noout : true ,
        nextupdate : true ,
        lastupdate : true ,
        crlnumber : true ,
    } , {stdout_encoding : 'utf8'});
    return parse_crl_output(stdout);
}


module.exports = inspect_crl;
