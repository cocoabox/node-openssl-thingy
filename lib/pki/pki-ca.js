const openssl = require('../openssl');
const create_conf_data = require('../create-conf-data');

const PkiChild = require('./pki-member');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const {write_temp_file} = require('./utils');
const PkiServer = require('./pki-server');
const PkiClient = require('./pki-client');
const {subject2obj} = require('../create-conf-data/utils');

class PkiCA extends PkiChild {
    /**
     *
     * @param {string} name
     * @param {string} subject
     * @param {Buffer} cert
     * @param {Buffer} privateKey
     * @param {Buffer} publicKey
     * @param {string} privateKeyPassword
     * @param {Buffer} csr
     * @param {string} database
     * @param {string} serial
     * @param {string} crl
     * @param {string} crlnumber
     */
    constructor(name = null , subject = null , cert = null , privateKey = null , publicKey = null ,
                privateKeyPassword = null , csr = null , database = null , serial = null ,
                crl = null , crlnumber = null , isRevoked = null) {
        super(name , subject , 'ca' , cert , privateKey , publicKey , privateKeyPassword , csr , isRevoked);
        this.database = database;
        this.serial = serial;
        this.crlnumber = crlnumber;
        this.crl = crl;
        this.children = {}; // Children dictionary {SERIAL: PkiChild}
    }

    // Serialize to JSON (includes CA-specific fields)
    toJSON() {
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

    // Static method to deserialize from JSON
    static fromJSON(json) {
        if ( typeof json === 'string' ) json = JSON.parse(json);
        if ( json?.type !== 'ca' ) throw new Error(`json.type must be "ca"; got instead : ${json?.type}`);
        const ca = new this(
            json.name ,
            json.subject ,
            PkiChild.deserializeBuffer(json.cert) ,
            PkiChild.deserializeBuffer(json.privateKey) ,
            PkiChild.deserializeBuffer(json.publicKey) ,
            json.privateKeyPassword ,
            json.csr ? PkiChild.deserializeBuffer(json.csr) : null ,
            json.database ,
            json.serial ,
            json.crl ? PkiChild.deserializeBuffer(json.crl) : null ,
            json.crlnumber ,
            json.isRevoked ,
        );

        // Deserialize children
        ca.children = Object.fromEntries(
            Object.entries(json.children).map(([serial , childJson]) => {
                const cls = {ca : PkiCA , client : PkiClient , server : PkiServer}[childJson?.type];
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
        if ( childNode instanceof PkiChild ) {
            childNode.parent = this;
            this.children[serial] = childNode;
            this.emit('updated' , {now_firing : this , why : 'add-child'});
        } else {
            throw new Error('Child must be an instance of PkiChild');
        }
    }

    /**
     * creates a new server and have the CA signed its cert
     * @param {...*} conf_args
     * @param {string|{days:number,common_name:string,country:string,city:string,organization_name:string,organization_unit:string,alt_names:string[],out_buffer:boolean}}  [conf_args[0]] common_name
     * @param {object} [conf_args[1]] options
     * @param {number} [conf_args[1].days  validity period of cert in days
     * @param {string} [conf_args[1].country]
     * @param {string} [conf_args[1].state]
     * @param {string} [conf_args[1].city]
     * @param {string} [conf_args[1].organization_name]
     * @param {string} [conf_args[1].organization_unit]
     * @param {string} [conf_args[1].alt_names]
     * @returns {Promise<PkiServer>}
     * @throws {Error}
     */
    async add_server(...conf_args) {
        const days = conf_args[conf_args.length - 1]?.days ?? 9999;
        const server = new PkiServer();
        try {
            await server.create_csr(...conf_args);
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
        this.emit('updated' , {now_firing : this , why : 'add-server'});
        return server;
    }

    async add_client(...conf_args) {
        const days = conf_args[conf_args.length - 1]?.days ?? 9999;
        const client = new PkiClient();
        try {
            await client.create_csr(...conf_args);
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
        this.emit('updated' , {now_firing : this , why : 'add-client'});
        return client;
    }

    async add_ca(...conf_args) {
        const ca = new PkiCA();
        try {
            await ca.create_csr(...conf_args);
        } catch (err) {
            console.warn('failed to create client CSR' , err);
            throw err;
        }
        try {
            const serial = await this.sign_csr_for_child(ca , {days : 9999});
            this.#add_child(serial , ca);
        } catch (err) {
            console.warn('failed to sign CSR for client' , err);
            throw err;
        }
        this.emit('updated' , {now_firing : this , why : 'add-ca'});
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
     * @returns {PkiChild|undefined}
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
            throw new Error('expecting serial/name/subject to be provided');
        }
    }

    /**
     * issue a CA cert for myself
     * @param {object} conf_args
     * @returns {Promise<Buffer>}
     */
    async create_cert(...conf_args) {
        const days = conf_args?.days ?? 9999;
        if ( ! this.privateKey ) await this.create_rsa_keypair();
        const {conf , name , subject} = create_conf_data.for_ca(...conf_args);
        this.csr = null;
        this.cert = await openssl.create_cert({
            private_key : this.privateKey ,
            conf ,
            days ,
        });
        this.name = name;
        this.subject = subject;
        this.emit('updated' , {now_firing : this , why : 'create-cert'});
        return this.cert;
    }

    /**
     * create a CSR for myself so a parent CA can sign it
     * @param conf_args
     * @returns {Promise<Buffer>}
     */
    async create_csr(...conf_args) {
        const {conf , name , subject} = create_conf_data.for_ca_csr(...conf_args);
        if ( ! this.privateKey ) await this.create_rsa_keypair();
        this.cert = null;
        this.csr = await openssl.create_csr({
            private_key : this.privateKey ,
            conf ,
        });
        this.name = name;
        this.subject = subject;
        this.emit('updated' , {now_firing : this , why : 'create-csr'});

        return this.csr;
    }

    async #do_ca_operation({before , operation} = {}) {
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
        const child_pki_member = child instanceof PkiChild ? child :
            typeof child === 'string' ? this.get_child({serial : child}) : null;
        if ( ! child_pki_member )
            throw new TypeError(`expecting child to be child serialnumber or PkiChild instance, got instead : ${child?.constructor?.name}`);
        const csr = child_pki_member.csr;
        if ( ! csr )
            throw new TypeError(`child has no csr`);
        if ( ! this.cert || ! this.privateKey )
            throw new Error('this.cert and this.privateKey are required to sign a csr');

        days = days ?? 9999;
        const out = {serial : null};
        const op_res = await this.#do_ca_operation({
            before : async ({serial}) => {
                out.serial = serial;
            } ,
            operation : async ({ca_config}) => {
                return await openssl.sign_csr({
                    csr ,
                    ca_config ,
                    ca_cert : this.cert ,
                    ca_private_key : this.privateKey ,
                    ca_private_key_password : this.privateKeyPassword ,
                    days ,
                });
            } ,
        });
        const signed_cert = op_res.result;
        if ( ! signed_cert )
            throw new Error('no signed cert returned; sign_csr() probably failed');
        child_pki_member.cert = signed_cert;
        this.emit('updated' , {now_firing : this , why : 'sign-csr'});
        return out.serial;
    }

    async revoke(child) {
        if ( ! (child instanceof PkiChild) ) {
            const child_ = this.get_child(child);
            if ( ! child_ )
                throw new RangeError(`no such child : ${child}`);
            child = child_;
        }
        const cert_to_revoke = child.cert;
        if ( ! child.cert )
            throw new Error(`child ${child.name} has no cert`);

        const out = {crlnumber : null};
        const res = await this.#do_ca_operation({
            before : async ({crlnumber}) => {
                out.crlnumber = crlnumber;
            } ,
            operation : async ({ca_config}) => {
                await openssl.revoke_cert({
                    cert_to_revoke ,
                    ca_config ,
                    ca_cert : this.cert ,
                    ca_private_key : this.privateKey ,
                    ca_private_key_password : this.privateKeyPassword ,
                });
            } ,
        });
        child.isRevoked = true;
        this.crl = null;
        this.emit('updated' , {now_firing : this , why : 'revoke'});

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
        const res = await this.#do_ca_operation({
            operation : async ({ca_config}) => {
                return await openssl.get_crl({
                    ca_config ,
                    ca_cert : this.cert ,
                    ca_private_key : this.privateKey ,
                    ca_private_key_password : this.privateKeyPassword ,
                });
            } ,
        });
        const crl = res.result;
        if ( ! crl )
            throw new Error('no crl returned; get_crl() probably failed');
        this.crl = crl;
        this.emit('updated' , {now_firing : this , why : 'get-crl'});

        return crl;
    }
}

module.exports = PkiCA;
