const openssl = require('../openssl');
const {EventEmitter} = require('node:events');

class PkiChild extends EventEmitter {
    #cert;
    #privateKey;
    #publicKey;

    constructor(name = null , subject = null , type = null , cert = null , privateKey = null ,
                publicKey = null , privateKeyPassword = null ,
                csr = null , isRevoked = null) {
        super();
        this.name = name;
        this.subject = subject;
        this.type = type;
        this.#cert = cert ? Buffer.from(cert) : null;
        this.#privateKey = privateKey ? Buffer.from(privateKey) : null;
        this.#publicKey = publicKey ? Buffer.from(publicKey) : null;
        this.privateKeyPassword = privateKeyPassword;
        this.csr = csr ? Buffer.from(csr) : null;
        this.isRevoked = isRevoked;

        // fire an "updated" event all the way to the root CA
        this.on('updated' , () => {
            const originates_from = this;
            let parent = this.parent;
            while (parent) {
                parent.emit('updated' , {now_firing : parent , why : 'child-updated' , originates_from});
                parent = parent.parent;
            }
        });
    }

    // Serialize to JSON
    toJSON() {
        return {
            name : this.name ,
            subject : this.subject ,
            type : '' ,
            cert : this.#cert ? `base64:${this.#cert.toString('base64')}` : null ,
            privateKey : this.#privateKey ? `base64:${this.#privateKey.toString('base64')}` : null ,
            publicKey : this.#publicKey ? `base64:${this.#publicKey.toString('base64')}` : null ,
            privateKeyPassword : this.privateKeyPassword ,
            csr : this.csr ? `base64:${this.csr.toString('base64')}` : null ,
            isRevoked : this.isRevoked ,
        };
    }

    get cert() {
        if ( this.isRevoked ) throw {error : 'revoked'};
        return this.#cert;
    }

    set cert(cert) {
        if ( this.isRevoked ) throw {error : 'revoked'};
        this.#cert = cert;
    }

    get privateKey() {
        if ( this.isRevoked ) throw {error : 'revoked'};
        return this.#privateKey;
    }

    get publicKey() {
        if ( this.isRevoked ) throw {error : 'revoked'};
        return this.#publicKey;
    }

    toString() {
        return JSON.stringify(this.toJSON());
    }

    static fromJSON(json) {
        throw new Error('abstract method');
    }

    static deserializeBuffer(data) {
        if ( data === null ) return;
        if ( data.startsWith('base64:') ) {
            return Buffer.from(data.slice(7) , 'base64');
        }
        return Buffer.from(data , 'utf8');
    }

    async create_rsa_keypair() {
        const k = await openssl.create_rsa_keypair({bits : 4096});
        this.#privateKey = k.private_key;
        this.#publicKey = k.public_key;
        this.emit('updated' , {now_firing : this , why : 'create-rsa-keypair'});
        return k;
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

    async get_pkcs12(export_password , {legacy} = {}) {
        const cert = this.cert;
        const private_key = this.privateKey;
        if ( ! cert || ! private_key ) throw new Error('both cert and private_key must be set');
        return await openssl.export_pkcs12({cert , private_key , export_password , legacy : !! legacy});
    }
}

module.exports = PkiChild;
