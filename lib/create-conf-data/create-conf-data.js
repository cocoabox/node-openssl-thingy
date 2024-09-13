/**
 * create INI file/ config text file data for use with openssl -config argument
 *
 * @param {object} sections {SECTION:{KEY:VAL, KEY2:VAL2,...}, SECTION2:{..}}
 * @param {boolean?} [out_buffer=true] if true returns a Buffer; else returns string
 * @returns {Buffer|string}
 */
function create_conf_data(sections , {out_buffer} = {}) {
    out_buffer = out_buffer ?? true;
    const out = ['#' , `# input sections : ${JSON.stringify(sections)}` , '#'];
    for ( const [section_name , kv] of Object.entries(sections) ) {
        out.push(`[${section_name}]`);
        for ( const [k , v] of Object.entries(kv) ) {
            if ( Array.isArray(v) ) {
                const v_comma_sep = v.map(v_elem => v_elem.toString('utf8')).join(',');
                out.push(`${k} = ${v_comma_sep}`);
            } else {
                out.push(`${k} = ${v}`);
            }
        }
        out.push('');
    }
    return out_buffer ? Buffer.from(out.join('\n')) : out.join('\n');
}


module.exports = create_conf_data;
