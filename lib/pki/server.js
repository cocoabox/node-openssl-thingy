const Child = require('./child');
const create_conf_data = require('../create-conf-data');


class Server extends Child {
    constructor(name = null , subject = null , cert = null , private_key = null , public_key = null , private_key_password = null , csr = null , is_revoked = null) {
        super(name , subject , 'server' , cert , private_key , public_key , private_key_password , csr , is_revoked);
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
            Child.deserialize_buffer(json.cert) ,
            Child.deserialize_buffer(json.private_key) ,
            Child.deserialize_buffer(json.public_key) ,
            json.private_key_password ,
            json.csr ? Child.deserialize_buffer(json.csr) : null ,
            json.is_revoked ,
        );
    }

    /**
     * Generates a Certificate Signing Request (CSR) based on the specified type (client or server) and configuration.
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
        const create_conf_data_func = create_conf_data.for_server;
        return await super.create_csr(create_conf_data_func , common_name , {key_args , conf_args});
    }
}

module.exports = Server;
