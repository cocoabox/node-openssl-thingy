const PkiChild = require('./pki-member');
const openssl = require('../openssl');
const create_conf_data = require('../create-conf-data');


class PkiServer extends PkiChild {
    constructor(name = null , subject = null , cert = null , privateKey = null , publicKey = null , privateKeyPassword = null , csr = null , isRevoked = null) {
        super(name , subject , 'server' , cert , privateKey , publicKey , privateKeyPassword , csr , isRevoked);
    }

    toJSON() {
        return {
            ...super.toJSON() ,
            type : 'server' ,
        };
    }

    // Static method to deserialize from JSON
    static fromJSON(json) {
        if ( typeof json === 'string' ) json = JSON.parse(json);
        if ( json?.type !== 'server' ) throw new Error(`need .type=="server" but got : ${json?.type}`);
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
     * generates CSR data for the server, then set the .csr property to be the CSR file data
     * finally resolves with the CSR file data (Buffer instance)
     * @param {...*} conf_args
     * @param {string|{common_name:string,country:string,city:string,organization_name:string,organization_unit:string,alt_names:string[],out_buffer:boolean}}  [conf_args[0]] common_name
     * @param {object} [conf_args[1]] options
     * @param {string} [conf_args[1].country]
     * @param {string} [conf_args[1].state]
     * @param {string} [conf_args[1].city]
     * @param {string} [conf_args[1].organization_name]
     * @param {string} [conf_args[1].organization_unit]
     * @param {string} [conf_args[1].alt_names]
     * @returns {Promise<Buffer>}
     */
    async create_csr(...conf_args) {
        const {conf , name , subject} = create_conf_data.for_server(...conf_args);
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

module.exports = PkiServer;
