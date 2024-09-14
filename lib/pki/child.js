const openssl = require('../openssl');
const {EventEmitter} = require('node:events');

class Child extends EventEmitter {
    #cert;
    #private_key;
    #public_key;

    constructor(name = null , subject = null , type = null , cert = null , private_key = null ,
                public_key = null , private_key_password = null ,
                csr = null , is_revoked = null) {
        super();
        this.name = name;
        this.subject = subject;
        this.type = type;
        this.#cert = cert ? Buffer.from(cert) : null;
        this.#private_key = private_key ? Buffer.from(private_key) : null;
        this.#public_key = public_key ? Buffer.from(public_key) : null;
        this.private_key_password = private_key_password;
        this.csr = csr ? Buffer.from(csr) : null;
        this.is_revoked = is_revoked;

    }

    emit_update(why , origin = this , set = new Set()) {
        if ( ! set.has(this) ) {
            set.add(this);
            this.emit('updated' , why , origin); // Emit the event with 'why' and 'origin'
            if ( this.parent ) {
                this.parent.emit_update(why , origin , set); // Bubble up to the parent
            }
        }
    }

    on_updated(listener) {
        this.on('updated' , listener);
    }


    // Serialize to JSON
    toJSON() {
        return {
            name : this.name ,
            subject : this.subject ,
            type : '' ,
            cert : this.#cert ? `base64:${this.#cert.toString('base64')}` : null ,
            private_key : this.#private_key ? `base64:${this.#private_key.toString('base64')}` : null ,
            public_key : this.#public_key ? `base64:${this.#public_key.toString('base64')}` : null ,
            private_key_password : this.private_key_password ,
            csr : this.csr ? `base64:${this.csr.toString('base64')}` : null ,
            is_revoked : this.is_revoked ,
        };
    }

    /**
     * returns the Buffer object to the x509 PEM cert
     * @returns {Buffer|undefined}
     */
    get cert() {
        if ( this.is_revoked ) throw {error : 'revoked'};
        return this.#cert;
    }

    set cert(cert) {
        if ( this.is_revoked ) throw {error : 'revoked'};
        this.#cert = cert;
    }

    /**
     * returns the Buffer object to the private key
     * @returns {Buffer|undefined}
     */
    get private_key() {
        if ( this.is_revoked ) throw {error : 'revoked'};
        return this.#private_key;
    }

    /**
     * returns the Buffer object to the public key
     * @returns {Buffer|undefined}
     */
    get public_key() {
        if ( this.is_revoked ) throw {error : 'revoked'};
        return this.#public_key;
    }

    /**
     * convert current object (including all children) to JSON string
     * @returns {Buffer|undefined}
     */
    toString() {
        return JSON.stringify(this.toJSON());
    }

    /**
     * convert a JSON string or JS object into a Child instance
     * @param {string|object} json
     * @return {Child}
     * @abstract
     */
    static fromJSON(json) {
        throw new Error('abstract method');
    }

    /**
     * convert a JSON string or JS object into a Child instance
     * @param {string|object} json
     * @return {Child}
     * @abstract
     */
    static from(json_or_str) {
        return this.fromJSON(json_or_str);
    }

    /**
     * convert base64 string, utf8 string to Buffer; if a Buffer object is passed then return it as-is
     * @param {String|buffer} data
     * @returns {Buffer|undefined}
     */
    static deserialize_buffer(data) {
        if ( typeof data === 'string' || data.startsWith('base64:') ) {
            return Buffer.from(data.slice(7) , 'base64');
        } else if ( typeof data === 'string' ) {
            return Buffer.from(data , 'utf8'); // string "abc" to --> Buffer <61h 62h 63h>
        } else if ( Buffer.isBuffer(data) ) {
            return Buffer;
        } else if ( data === null ) {
            // return undefined
        } else {
            throw new TypeError(`expecting data to be Buffer,string or null ; got instead : ${data}`);
        }
    }

    /**
     * Note: for mbedTLS; the max number of bit is 2048
     * @param {number} [bits=4096]
     * @param {string?} password
     * @returns {Promise<{public_key: Buffer, password?: string, private_key: Buffer}>}
     */
    async create_rsa_keypair({bits = 4096 , password} = {}) {
        const k = await openssl.create_rsa_keypair({bits , password});
        this.#private_key = k.private_key;
        this.#public_key = k.public_key;
        this.emit_update('create-rsa-keypair');
        return k;
    }

    /**
     * @param {string} [mode='p256']
     * @param {string?} password
     * @returns {Promise<{public_key: Buffer, password?: string, private_key: Buffer}>}
     */
    async create_ecdsa_keypair({mode = 'p256' , password} = {}) {
        const k = await openssl.create_ecdsa_keypair({mode , password});
        this.#private_key = k.private_key;
        this.#public_key = k.public_key;
        this.emit_update('create-ecdsa-keypair');
        return k;
    }

    /**
     * @param {string} algorithm
     * @param {object} options
     * @param {string?} options.password (common)
     * @param {number?} options.bits (for rsa only) for mbedtls, max bit is 2048
     * @param {string?} options.mode (for ecdsa only) should be p256 (default) or p384
     * @returns {Promise<{public_key: Buffer, password?: string, private_key: Buffer}|*>}
     */
    async create_keypair(algorithm , options = {}) {
        switch (algorithm.toLowerCase()) {
            case 'rsa':
                return await this.create_rsa_keypair(options);
            case 'ecdsa':
                return await this.create_ecdsa_keypair(options);
            default:
                throw new RangeError(`expecting algorithm to be "rsa" or "ecdsa"; got ${algorithm}`);
        }
    }

    /**
     * return Cert chain : ME+PARENT+GRANDPARENT
     * @returns {Buffer}
     */
    get cert_chain() {
        const certs = [];
        let node = this;
        do {
            if ( ! node.cert ) throw new Error(`node ${node.name} has no cert`);
            certs.push(node.cert);
            node = node.parent;
        } while (node);
        return Buffer.concat(certs);
    }

    async get_pkcs12(export_password , {legacy = false} = {}) {
        const cert = this.cert;
        const private_key = this.private_key;
        if ( ! cert || ! private_key ) throw new Error('both cert and private_key must be set');
        return await openssl.export_pkcs12({cert , private_key , export_password , legacy : !! legacy});
    }

    /**
     * Generates a Certificate Signing Request (CSR) based on the specified type (client or server) and configuration.
     * If a private key does not already exist, a new key pair is generated using the provided key options.
     * @param {function} create_conf_data_func the create_conf function that we'll use to create the Config file Buffer
     * @param {string} common_name - The common name (CN) to be included in the CSR, typically the fully qualified domain name.
     * @param {Object} [key_args={}] - Optional configuration for key generation. The object may include:
     * @param {string} [key_args.key_algorithm='rsa'] - The algorithm to be used for generating the private key. Default is 'rsa'.
     * @param {Object} [key_args.key_options={bits: 4096}] - Options for key generation, such as the key size. Default is a key with 4096 bits.
     * @param {string} [key_args.key_password] - An optional password for encrypting the private key.
     * @param {Object} [conf_args={}] - Optional additional configuration parameters that will be merged with the common name.
     * @returns {Promise<Buffer>} A promise that resolves to a Buffer containing the CSR data.
     * @throws {Error} Throws an error if the private key cannot be created, if the configuration data is invalid, or if CSR generation fails.
     */
    async create_csr(create_conf_data_func , common_name , {key_args = {} , conf_args = {}}) {
        // extract key-related arguments from the last dict element
        const {
            key_algorithm = 'rsa' ,
            key_options = {bits : 4096} ,
            key_password ,
        } = key_args ?? {};

        const create_conf_data_func_arg = Object.assign({} , {common_name} , conf_args);
        const {conf , name , subject} = create_conf_data_func(create_conf_data_func_arg);
        if ( ! this.private_key ) {
            await this.create_keypair(
                key_algorithm ,
                Object.assign({} , key_options , {password : key_password}) ,
            );
        }
        this.cert = null;
        this.csr = await openssl.create_csr({
            private_key : this.private_key ,
            conf ,
        });
        this.name = name;
        this.subject = subject;
        this.emit_update('create-csr');
        return this.csr;
    }

    #path_cached;

    /**
     * get an absolute path to this node in the form : /SERIAL_OF_CA/SERIAL_OF_CA/SERIAL_OF_SERVER
     * the root CA has path "/" and the first intermediate CA under the root is "/01" or something like that
     * where "01" is the serial of that intermediate CA.
     *
     * @returns {String}
     */
    get path() {
        if ( this.#path_cached ) return this.#path_cached;
        const get_serial_of = (whom , parent) => {
            if ( ! parent ) return;
            return Object.entries(parent?.children ?? {})
                .find(([, pki_child]) => pki_child === whom) ?.[0];
        };
        const path = [];
        for ( let leaf = this; !! leaf; leaf = leaf.parent ) {
            const serial = get_serial_of(leaf , leaf.parent);
            if ( typeof serial !== 'undefined' ) path.unshift(serial);
        }
        this.#path_cached = path.length === 0 ? '/' : ('/' + path.join('/'));
        return this.#path_cached;
    }
}

module.exports = Child;
