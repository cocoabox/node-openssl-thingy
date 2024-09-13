const PkiChild = require('./pki-member');
const openssl = require('../openssl');
const create_conf_data = require('../create-conf-data');


class PkiClient extends PkiChild {
    constructor(name = null , subject = null , cert = null , privateKey = null ,
                publicKey = null , privateKeyPassword = null , csr = null , isRevoked = null) {
        super(name , subject , 'client' , cert , privateKey , publicKey , privateKeyPassword , csr , isRevoked);
    }

    toJSON() {
        return {
            ...super.toJSON() ,
            type : 'client' ,
        };
    }

    // Static method to deserialize from JSON
    static fromJSON(json) {
        if ( typeof json === 'string' ) json = JSON.parse(json);
        if ( json?.type !== 'client' ) throw new Error(`need .type=="client" but got : ${json?.type}`);
        return new this(
            json.name ,
            json.subject ,
            PkiChild.deserializeBuffer(json.cert) ,
            PkiChild.deserializeBuffer(json.privateKey) ,
            PkiChild.deserializeBuffer(json.publicKey) ,
            json.privateKeyPassword ,
            json.csr ? PkiChild.deserializeBuffer(json.csr) : null ,
            json.isRevoked ,
        );
    }

    /**
     * create a CSR for myself so a parent CA can sign it
     * @param conf_args
     * @returns {Promise<Buffer>}
     */
    async create_csr(...conf_args) {
        const {conf , name , subject} = create_conf_data.for_client(...conf_args);
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
}

module.exports = PkiClient;
