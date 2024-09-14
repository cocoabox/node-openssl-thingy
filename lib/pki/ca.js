const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const openssl = require('../openssl');
const create_conf_data = require('../create-conf-data');
const Child = require('./child');
const Server = require('./server');
const Client = require('./client');

const {write_temp_file} = require('./utils');
const {subject2obj} = require('../create-conf-data/utils');

class CA extends Child {
    /**
     *
     * @param {string} name
     * @param {string} subject
     * @param {Buffer} cert
     * @param {Buffer} private_key
     * @param {Buffer} public_key
     * @param {string} private_key_password
     * @param {Buffer} csr
     * @param {string} database
     * @param {string} serial
     * @param {string} crl
     * @param {string} crlnumber
     */
    constructor(name = null , subject = null , cert = null , private_key = null , public_key = null ,
                private_key_password = null , csr = null , database = null , serial = null ,
                crl = null , crlnumber = null , is_revoked = null) {
        super(name , subject , 'ca' , cert , private_key , public_key , private_key_password , csr , is_revoked);
        this.database = database;
        this.serial = serial;
        this.crlnumber = crlnumber;
        this.crl = crl;
        this.children = {}; // Children dictionary {SERIAL: Child}
    }

    /**
     * convert this CA object to a generic Javscript object ; to convert to JSON text, apply JSON.stringify() on
     * the returned result
     * @returns {{crlnumber:*, database:*, serial:*, children: {[p: string]: object}, type: *, crl:*}}
     */
    toJSON() {
        // Serialize to JSON (includes CA-specific fields)
        return {
            ...super.toJSON() ,
            type : 'ca' ,
            database : this.database ,
            serial : this.serial ,
            crl : this.crl ? `base64:${this.crl.toString('base64')}` : null ,
            crlnumber : this.crlnumber ,
            children : Object.fromEntries(
                Object.entries(this.children).map(([serial , child]) => [serial , child.toJSON()])
            )
        };
    }

    /**
     * convert a JS object or JSON string into a CA object
     * @param {string|object} json
     * @returns {CA}
     */
    static fromJSON(json) {
        if ( typeof json === 'string' ) json = JSON.parse(json);
        if ( json?.type !== 'ca' ) throw new Error(`json.type must be "ca"; got instead : ${json?.type}`);
        const ca = new this(
            json.name ,
            json.subject ,
            Child.deserialize_buffer(json.cert) ,
            Child.deserialize_buffer(json.private_key) ,
            Child.deserialize_buffer(json.public_key) ,
            json.private_key_password ,
            json.csr ? Child.deserialize_buffer(json.csr) : null ,
            json.database ,
            json.serial ,
            json.crl ? Child.deserialize_buffer(json.crl) : null ,
            json.crlnumber ,
            json.is_revoked ,
        );

        // Deserialize children
        ca.children = Object.fromEntries(
            Object.entries(json.children).map(([serial , childJson]) => {
                const cls = {ca : CA , client : Client , server : Server}[childJson?.type];
                if ( ! cls )
                    throw new Error(`unknown .type while deserializing : ${JSON.stringify(childJson)} ; need "ca", "client" or "server"`);
                return [
                    serial ,
                    cls.fromJSON(childJson)
                ];
            })
        );
        for ( const child of Object.values(ca.children) ) {
            child.parent = ca;
        }
        return ca;
    }

    #add_child(serial , childNode) {
        if ( childNode instanceof Child ) {
            childNode.parent = this;
            this.children[serial] = childNode;
            this.emit_update('add-child' , this);
        } else {
            throw new Error('Child must be an instance of Child');
        }
    }


    /**
     * create a server key-pair and cert and have the CA signed that cert
     * @param {string|object} common_name CN of the server
     * @param {number?} [days=9999]
     * @param {object?} key_args
     * @param {string?} [key_args.key_algorithm='rsa']
     * @param {object?} [key_args.key_options={bits:4096}]
     * @param {string?} key_args.key_password
     * @param {object?} conf_args
     * @param {string?} conf_args.country
     * @param {string?} conf_args.state
     * @param {string?} conf_args.city
     * @param {string?} conf_args.organization_name
     * @param {string?} conf_args.organization_unit
     * @param {string[]?} conf_args.alt_names
     * @returns {Promise<Server>}
     */
    async add_server(common_name , {
                         days = 9999 ,
                         key_args = {} ,
                         conf_args ,
                     } = {}
    ) {
        if ( typeof common_name === 'object' && common_name?.hasOwnProperty('common_name') ) {
            conf_args = common_name.conf_args;
            key_args = common_name.key_args;
            days = common_name.days;
            common_name = common_name.common_name;
        }
        const server = new Server();
        try {
            await server.create_csr(common_name , {key_args , conf_args});
        } catch (err) {
            console.warn('failed to create server CSR' , err);
            throw err;
        }
        try {
            const serial = await this.sign_csr_for_child(server , {days});
            this.#add_child(serial , server);
        } catch (err) {
            console.warn('failed to sign CSR for server' , err);
            throw err;
        }
        this.emit_update('add-server' , this);
        return server;
    }

    /**
     * create a client key-pair and cert and have the CA signed that cert
     * @param {string|object} common_name CN of the server
     * @param {number?} [days=9999]
     * @param {object?} key_args
     * @param {string?} [key_args.key_algorithm='rsa']
     * @param {object?} [key_args.key_options={bits:4096}]
     * @param {string?} key_args.key_password
     * @param {object?} conf_args
     * @param {string?} conf_args.country
     * @param {string?} conf_args.state
     * @param {string?} conf_args.city
     * @param {string?} conf_args.organization_name
     * @param {string?} conf_args.organization_unit
     * @param {string|string[]?} conf_args.email
     * @returns {Promise<Server>}
     */
    async add_client(common_name , {
                         days = 9999 ,
                         key_args = {} ,
                         conf_args ,
                     } = {}
    ) {
        if ( typeof common_name === 'object' && common_name?.hasOwnProperty('common_name') ) {
            conf_args = common_name.conf_args;
            key_args = common_name.key_args;
            days = common_name.days;
            common_name = common_name.common_name;
        }
        const client = new Client();
        try {
            await client.create_csr(common_name , {key_args , conf_args});
        } catch (err) {
            console.warn('failed to create client CSR' , err);
            throw err;
        }
        try {
            const serial = await this.sign_csr_for_child(client , {days});
            this.#add_child(serial , client);
        } catch (err) {
            console.warn('failed to sign CSR for client' , err);
            throw err;
        }
        this.emit_update('add-client');
        return client;
    }

    /**
     * create an intermediate key-pair and cert and have the current parental CA signed that cert
     * @param {string|object} common_name CN of the server
     * @param {number?} [days=9999]
     * @param {object?} key_args
     * @param {string?} [key_args.key_algorithm='rsa']
     * @param {object?} [key_args.key_options={bits:4096}]
     * @param {string?} key_args.key_password
     * @param {object?} conf_args
     * @param {string?} conf_args.country
     * @param {string?} conf_args.state
     * @param {string?} conf_args.city
     * @param {string?} conf_args.organization_name
     * @param {string?} conf_args.organization_unit
     * @param {string[]?} conf_args.alt_names
     * @returns {Promise<Server>}
     */
    async add_ca(common_name , {
                     days = 9999 ,
                     key_args = {} ,
                     conf_args ,
                 } = {}
    ) {
        if ( typeof common_name === 'object' && common_name?.hasOwnProperty('common_name') ) {
            conf_args = common_name.conf_args;
            key_args = common_name.key_args;
            days = common_name.days;
            common_name = common_name.common_name;
        }
        const ca = new CA();
        try {
            await ca.create_csr(common_name , {key_args , conf_args});
        } catch (err) {
            console.warn('failed to create client CSR' , err);
            throw err;
        }
        try {
            const serial = await this.sign_csr_for_child(ca , {days});
            this.#add_child(serial , ca);
        } catch (err) {
            console.warn('failed to sign CSR for client' , err);
            throw err;
        }
        this.emit_update('add-ca');
        return ca;
    }

    /**
     * find the first matching child using serial,name,subject
     * @param {string|number|{serial:number|string,name:string,subject:object}} serial
     *      to search by serial, pass a number or a hex string e.g. "05" or {serial:number|string}
     * @param {string} name
     *      to search by child.name (exact match) pass the name, or {name:NAME_STR}
     * @param {object|string} subject
     *      to search by one or more subject fields e.g. "state=CA, city=Los Angeles, OU=org", either
     *      pass a string: wrapped in {subject:**}, i.e.
     *          {subject:'S=CA/L=Los Angeles/OU=org'}
     *          or a dict : {subject:{S:'CA',L:'Los Angeles',OU:'org'}}
     *      order is not important, but all fields specified here must be satisfied
     * @returns {Child|undefined}
     */
    get_child({serial , name , subject} = {}) {
        const find_child_by_serial = (ser) => {
            const entry = Object.entries(this.children)
                .map(([k , v]) => [parseInt(k , 16) , v])
                .find(([numerical_serial , v]) => ser === numerical_serial);
            if ( entry ) return entry[1];
        };

        if ( typeof arguments[0] === 'string' ) {
            return find_child_by_serial(parseInt(arguments[0] , 16));

        } else if ( typeof arguments[0] === 'number' ) {
            return find_child_by_serial(arguments[0]);

        } else if ( serial ) {
            return find_child_by_serial(typeof serial === 'number' ? serial : parseInt(arguments[0] , 16));
        } else if ( name ) {
            // find by name
            const entry = Object.entries(this.children)
                .find(([, v]) => v.name === name);
            if ( entry ) return entry[1];
        } else if ( subject ) {
            function isNeedleInHaysack(haysack , needle) {
                return Object.entries(needle).every(([key , value]) => haysack[key] === value);
            }

            const subject_obj = typeof subject === 'string' ? subject2obj(subject) : subject;
            const entry = Object.entries(this.children)
                .find(([, v]) => {
                    const v_subject_obj = subject2obj(v.subject);
                    return isNeedleInHaysack(v_subject_obj , subject_obj);
                });
            if ( entry ) return entry[1];
        } else {
            const args = JSON.stringify(Array.from(arguments));
            throw new Error(`expecting serial/name/subject to be provided ; called with args : ${args}`);
        }
    }

    /**
     * Generates keypair and self-signed cert for myself
     * @param {function} create_conf_data_func the create_conf function that we'll use to create the Config file Buffer
     * @param {string} common_name - The common name (CN) to be included in the CSR, typically the fully qualified domain name.
     * @param {Object} [key_args={}] - Optional configuration for key generation. The object may include:
     * @param {string} [key_args.key_algorithm='rsa'] - The algorithm to be used for generating the private key. Default is 'rsa'.
     * @param {Object} [key_args.key_options={bits: 4096}] - Options for key generation, such as the key size. Default is a key with 4096 bits.
     * @param {string} [key_args.key_password] - An optional password for encrypting the private key.
     * @param {Object} [conf_args={}] - Optional additional configuration parameters that will be merged with the common name.
     * @param {string[]?} [conf_args.alt_names] - optional alt DNS names for the CA
     * @returns {Promise<Buffer>} A promise that resolves to a Buffer containing cert data.
     * @throws {Error} Throws an error if the private key cannot be created, if the configuration data is invalid, or if CSR generation fails.
     */
    async create_cert(common_name , {conf_args = {} , key_args = {} , days = 9999} = {}) {
        const {
            key_algorithm = 'rsa' ,
            key_options = {bits : 4096} ,
            key_password ,
        } = key_args ?? {};
        if ( ! this.private_key ) {
            await this.create_keypair(
                key_algorithm ,
                Object.assign({} , key_options , {password : key_password}) ,
            );
        }
        const {conf , name , subject} = create_conf_data.for_ca(common_name , conf_args);
        this.csr = null;
        this.cert = await openssl.create_cert({
            private_key : this.private_key ,
            conf ,
            days ,
        });
        this.name = name;
        this.subject = subject;
        this.emit_update('create-cert');
        return this.cert;
    }

    /**
     * Generates a Certificate Signing Request (CSR) based on the specified type (client or server or CA) and configuration.
     * If a private key does not already exist, a new key pair is generated using the provided key options.
     *
     * @param {string} client_or_server - Specifies the type of CSR to create. Should be either 'client' or 'server'.
     * @param {string} common_name - The common name (CN) to be included in the CSR, typically the fully qualified domain name.
     * @param {Object} [key_args={}] - Optional configuration for key generation. The object may include:
     *   @param {string} [key_args.key_algorithm='rsa'] - The algorithm to be used for generating the private key. Default is 'rsa'.
     *   @param {Object} [key_args.key_options={bits: 4096}] - Options for key generation, such as the key size. Default is a key with 4096 bits.
     *   @param {string} [key_args.key_password] - An optional password for encrypting the private key.
     * @param {Object} [conf_args={}] - e.g. {country:**, city:**, ...}
     * @param {string[]?} [conf_args.alt_names] alt DNS names for the server, if any
     * @returns {Promise<Buffer>} A promise that resolves to a Buffer containing the CSR data.
     * @throws {Error} Throws an error if the private key cannot be created, if the configuration data is invalid, or if CSR generation fails.
     */
    async create_csr(common_name , {key_args = {} , conf_args = {}}) {
        const create_conf_data_func = create_conf_data.for_ca;
        return await super.create_csr(create_conf_data_func , common_name , {key_args , conf_args});
    }

    async #do_ca_operation(ext , {before , operation} = {}) {
        if ( ! this.crlnumber ) this.crlnumber = '00';
        const crlnumber = this.crlnumber.trim();
        const crlnumber_temp_path = await write_temp_file(this.crlnumber , 'utf8');

        if ( ! this.serial ) this.serial = '00';
        const serial = this.serial.trim();
        const serial_temp_path = await write_temp_file(this.serial , 'utf8');

        if ( ! this.database ) this.database = '';
        const database_temp_path = await write_temp_file(this.database , 'utf8');

        if ( typeof before === 'function' ) await before({crlnumber , serial});

        const new_cert_dir = await fs.promises.mkdtemp(path.join(os.tmpdir() , 'new-cert-dir'));

        const ca_config = create_conf_data.for_ca_operations({
            ext ,
            serial : serial_temp_path ,
            crlnumber : crlnumber_temp_path ,
            database : database_temp_path ,
            new_certs_dir : new_cert_dir ,
        }).conf;

        const result = await operation({ca_config});

        this.crlnumber = await fs.promises.readFile(crlnumber_temp_path , 'utf8');
        this.serial = await fs.promises.readFile(serial_temp_path , 'utf8');
        this.database = await fs.promises.readFile(database_temp_path , 'utf8');

        await fs.promises.rm(crlnumber_temp_path);
        await fs.promises.rm(serial_temp_path);
        await fs.promises.rm(database_temp_path);
        await fs.promises.rm(new_cert_dir , {recursive : true});

        return {
            crlnumber : this.crlnumber ,
            serial : this.serial ,
            database : this.database ,
            result ,
        };

    }

    async sign_csr_for_child(child , {days} = {}) {
        const child_pki_member = child instanceof Child ? child :
            typeof child === 'string' ? this.get_child({serial : child}) : null;
        if ( ! child_pki_member )
            throw new TypeError(`expecting child to be child serialnumber or Child instance, got instead : ${child?.constructor?.name}`);
        const csr = child_pki_member.csr;
        if ( ! csr )
            throw new TypeError(`child has no csr`);
        if ( ! this.cert || ! this.private_key )
            throw new Error('this.cert and this.private_key are required to sign a csr');

        days = days ?? 9999;
        const out = {serial : null};
        const ext = {Server : 'server' , Client : 'client' , CA : 'ca'}[child_pki_member.constructor.name];
        const op_res = await this.#do_ca_operation(ext , {
            before : async ({serial}) => {
                out.serial = serial;
            } ,
            operation : async ({ca_config}) => {
                return await openssl.sign_csr({
                    csr ,
                    ca_config ,
                    ca_cert : this.cert ,
                    ca_private_key : this.private_key ,
                    ca_private_key_password : this.private_key_password ,
                    days ,
                });
            } ,
        });
        const signed_cert = op_res.result;
        if ( ! signed_cert )
            throw new Error('no signed cert returned; sign_csr() probably failed');
        child_pki_member.cert = signed_cert;
        this.emit_update('sign-csr');
        return out.serial;
    }

    async revoke(child) {
        if ( ! child ) {
            throw new RangeError('child is empty, expecting Child instance or search parameter e.g. {name:***}');
        }
        if ( ! (child instanceof Child) ) {
            const child_ = this.get_child(child);
            if ( ! child_ )
                throw new RangeError(`no such child : ${child}`);
            child = child_;
        }
        const cert_to_revoke = child.cert;
        if ( ! child.cert )
            throw new Error(`child ${child.name} has no cert`);

        const out = {crlnumber : null};
        const ext = {Server : 'server' , Client : 'client' , CA : 'ca'}[child.constructor.name];
        const res = await this.#do_ca_operation(ext , {
            before : async ({crlnumber}) => {
                out.crlnumber = crlnumber;
            } ,
            operation : async ({ca_config}) => {
                await openssl.revoke_cert({
                    cert_to_revoke ,
                    ca_config ,
                    ca_cert : this.cert ,
                    ca_private_key : this.private_key ,
                    ca_private_key_password : this.private_key_password ,
                });
            } ,
        });
        child.is_revoked = true;
        this.crl = null;
        this.emit_update('revoke');

    }

    async get_crl_info() {
        if ( ! this.crl ) {
            this.crl = await this.get_crl();
        }
        return await openssl.inspect_crl(this.crl);
    }

    async get_crl({force} = {}) {
        if ( this.crl ) {
            if ( ! force ) {
                // return CRL if still valid
                const {next_update} = await openssl.inspect_crl(this.crl);
                const now = new Date;
                if ( now <= next_update ) {
                    console.warn('use cached CRL');
                    return this.crl;
                }
            }
        }
        const res = await this.#do_ca_operation('' , {
            operation : async ({ca_config}) => {
                return await openssl.get_crl({
                    ca_config ,
                    ca_cert : this.cert ,
                    ca_private_key : this.private_key ,
                    ca_private_key_password : this.private_key_password ,
                });
            } ,
        });
        const crl = res.result;
        if ( ! crl )
            throw new Error('no crl returned; get_crl() probably failed');
        this.crl = crl;
        this.emit_update('get-crl');
        return crl;
    }
}

module.exports = CA;
