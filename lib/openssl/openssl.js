const {spawn} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function get_temp_path() {
    return path.join(os.tmpdir() , `openssl_temp_${Date.now()}_${Math.random()}`);
}

async function write_temp_file(buffer , opt) {
    const temp_path = get_temp_path();
    await fs.promises.writeFile(temp_path , buffer , opt);
    return temp_path;
}

/**
 * runs the openssl command
 * @param {string} action
 *      openssl subcommand, e.g. "x509"
 * @param {object} openssl_args
 *      must be in key-value format, e.g. {days:999, x509:true, new:true} --> "-days 999 -x509 -new"
 *      if there is no value, e.g. "-x509" then pass "" or true as value
 *      to specify input/output files:
 *      - to use a Buffer object for an arg, e.g. -inkey KEY_DATA_BUFFER, pass : {'inkey':BUFFER_INSTANCE}
 *      - to write out to a Buffer object, e.g. -out OUT_CERT, pass the Buffer class : {'outkey':Buffer}
 *              and receive the Buffer like this : const {outkey} = await openssl(...);
 *      - to write out to a Buffer object and return it in a customized key, pass : {'out':{OUT_KEY_NAME:Buffer}}
 *              and receive OUT_KEY_NAME like this : const {OUT_KEY_NAME} = await openssl(...);
 *      to specify passwords:
 *      - for e.g. -passin CERT_PASSWORD, pass: {passin: 'pass:CERT_PASSWORD'}
 * @param {Buffer?} [stdin=null]
 * @param {string?} [openssl_location='openssl']
 * @param {string?} [stdout_encoding=null] if none then stdout encoding is binary
 * @param {boolean?} [reject_on_non_zero_exit_code=true] if openssl app has exit code >0 then reject
 * @param {number?} [timeout=1000] timeout in msec
 * @param {boolean|function?} [show_stderr=false]
 *      if true, then stderr will be emitted via : console.warn ; if a function is provided, it will be used
 *      in place of console.warn
 * @returns {Promise<{}>}
 */
async function openssl(action , openssl_args , {
                           stdin ,
                           openssl_location = 'openssl' ,
                           stdout_encoding = 'utf8' ,
                           reject_on_non_zero_exit_code = true ,
                           timeout = 2500 ,
                           show_stderr = false ,
                       } = {}
) {
    const temp_files = [];
    const out_files = {};
    const conf_files = {}; //  {argname: content_str, ...}
    const args = [action];
    // reformat openssl_args into proper command line args, append them to $args above
    for ( const [k , value] of Object.entries(openssl_args) ) {
        // in case you gave '-arg': ***
        const key = k?.[0] === '-' ? k.substring(1) : k;
        if ( typeof value === 'object'
            && Object.entries(value).length === 1
            && Object.values(value)[0] === Buffer
        ) {
            // outkey:{private_key:Buffer} ==> -outkey TEMP_LOCAITON
            // returns: out.private_key == Buffer
            const out_key = Object.keys(value)[0];
            const tempPath = get_temp_path();
            temp_files.push(tempPath);
            out_files[out_key] = tempPath;
            args.push(`-${key}`);
            args.push(tempPath);
        } else if ( value === Buffer ) {
            // outkey:Buffer ==> -outkey TEMP_LOCAITON
            // returns: out.outkey == Buffer
            const tempPath = get_temp_path();
            temp_files.push(tempPath);
            out_files[key] = tempPath;
            args.push(`-${key}`);
            args.push(tempPath);
        } else if ( Buffer.isBuffer(value) ) {
            const tempPath = await write_temp_file(value);
            temp_files.push(tempPath);
            args.push(`-${key}`);
            args.push(tempPath);
            if ( key.toLowerCase().includes('conf') ) {
                conf_files[tempPath] = value.toString('utf8');
            }
        } else if ( value === true || value === '' ) {
            args.push(`-${key}`);
        } else if ( value ) {
            args.push(`-${key}`);
            args.push(`${value}`);
            if ( value === 'stdout' ) {
                stdout_encoding = null;
            }
        } else if ( value === false ) {
            // do nothing
        } else {
            throw {error : 'bad-arg' , key , value};
        }
    }
    const print_error_func = typeof show_stderr === 'function' ? show_stderr : show_stderr === false ? () => {
    } : console.warn;
    const out = {};
    const stdout = [];
    const stderr = [];
    let error_thrown;
    try {
        const timeout_timer = timeout ? setTimeout(() => {
            print_error_func('timeout ; stderr was :' , Buffer.concat(stderr).toString('utf8'));
            throw {error : 'timeout'};
        } , timeout) : null;
        // console.warn('## [verbose] run openssl : ' , [].concat([openssl_location] , args).join(' '));
        const openssl_process = spawn(openssl_location , args);
        // Write to stdin if stdinData is provided
        if ( stdin ) {
            openssl_process.stdin.write(stdin);
            openssl_process.stdin.end();
        }
        if ( stdout_encoding ) {
            openssl_process.stdout.setEncoding(stdout_encoding);
        }
        openssl_process.stdout.on('data' , data => stdout.push(data));
        openssl_process.stderr.on('data' , data => {
            if ( show_stderr ) {
                print_error_func(data.toString('utf8'));
            }
            stderr.push(data);
        });
        const {exit_code} = await new Promise((resolve , reject) => {
            openssl_process.on('close' , exit_code => {
                if ( timeout_timer ) clearTimeout(timeout_timer);
                resolve({exit_code});
            });
        });
        out.exit_code = exit_code;
        if ( exit_code > 0 ) {
            out.error = true;
            out.__openssl_cmd__ = openssl_location;
            out.__openssl_args__ = args;
            out.__openssl_config_files__ = conf_files;
        }
    } catch (err) {
        out.error = err?.error ?? {'unknown-error' : err};
        out.__openssl_cmd__ = openssl_location;
        out.__openssl_args__ = args;
        out.__openssl_config_files__ = conf_files;
        out.stderr = Buffer.concat(stderr);
        error_thrown = true;
    } finally {
        out.stdout = stdout_encoding ? stdout.join('') : Buffer.concat(stdout);
        out.stderr = Buffer.concat(stderr).toString('utf8');
        for ( const [out_key , out_path] of Object.entries(out_files) ) {
            try {
                out[out_key] = await fs.promises.readFile(out_path);
            } catch (error) {
                out[out_key] = {error};
            }
        }
        await Promise.all(temp_files.map(tf => fs.existsSync(tf) && fs.promises.rm(tf)));
    }
    if ( error_thrown || (out.error && reject_on_non_zero_exit_code) ) {
        print_error_func('openssl command failed' +
            `\n\t- stderr : ${out.stderr.split('\n').map(l => `\n\t    ${l}`).join('')}` +
            `\n\t- command : ${openssl_location} ${args.join(' ')}\n` +
            Object.entries(conf_files).map(([fn , body]) => {
                fn = `\t- config file : ${fn}\n`;
                body = body.split('\n').map(line => `\t    ${line}`).join('\n');
                return [fn , body];
            }).join('\n')
        );
        throw out;
    } else {
        return out;
    }
}

module.exports = openssl;
