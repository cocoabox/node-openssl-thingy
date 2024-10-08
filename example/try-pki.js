#!/usr/bin/env node

const {pki} = require('../lib');
const {CA} = pki;
const {inspect} = require('node:util');
const fsPromises = require('node:fs').promises;

(async function () {
    try {
        // use 2048 bit for embedded system (mbedtls) compatibility
        const key_args = {
            key_algorithm : 'rsa' ,
            key_options : {bits : 2048} ,
        };
        const root_ca = new CA();
        // write to disk whenever the Root CA updates
        root_ca.on_updated(async (why , origin) => {
            console.log(`  .. writing because ${why} from : ${origin?.name ?? 'no-name'} (${origin?.path})`);
            await fsPromises.writeFile('root-ca.json' , root_ca.toString() , 'utf8');
        });

        console.warn('create root CA');
        await root_ca.create_cert('my_root_ca' , {
            key_args ,
            conf_args : {
                country : 'JP' ,
                state : 'Tokyo' ,
                city : 'Spam City' ,
                organization_name : 'Ham Corp' ,
                organization_unit : 'Egg Dept' ,
                alt_names : ['my-root-ca' , 'my-root-ca.local' , '*.my-root-ca.local'] ,
            } ,
            days : 9999 ,
        });

        console.warn('create server');
        await root_ca.add_server('my_server' , {
            days : 9999 ,
            conf_args : {
                alt_names : ['my-server' , 'my-server.local' , '*.my-server.local'] ,
                // since no contact info is supplied, we'll use default supplied in : default-distinguished-name.js
            } ,
            key_args ,
        });

        console.warn('create user');
        await root_ca.add_client('user1' , 'user1@my_server' , {
            conf_args : {
                country : 'JP' ,
                state : 'Gunma' ,
                city : 'Hoge City' ,
            } ,
            days : 9999 ,
            key_args ,
        });

        console.warn('create intermediate CA');
        const inte_ca = await root_ca.add_ca('intermediate-ca' , {
            conf_args : {alt_names : ['inte-ca' , 'inte-ca.local' , '*.inte-ca.local']} ,
            key_args ,
            days : 9999 ,
        });
        await fsPromises.writeFile('inte_ca.pem' , inte_ca.cert);

        console.warn('create server under intermediate CA');
        const server2 = await inte_ca.add_server('my_server2' , {
            conf_args : {alt_names : ['my-server2' , 'my-server2.local' , '*.my-server2.local']} ,
            key_args ,
            days : 9999 ,
        });

        console.warn('create another intermediate CA');
        const another_inte_ca = await inte_ca.add_ca('another-intermediate-ca' , {
            conf_args : {alt_names : ['another-inte-ca' , 'another-inte-ca.local' , '*.another-inte-ca.local']} ,
            key_args ,
            days : 9999 ,
        });

        console.warn('create another server');
        const another_server = await another_inte_ca.add_server('another_server' , {
            days : 365 ,
            conf_args : {alt_names : ['another-server' , 'another-server.local' , '*.another-server.local']} ,
            key_args ,
        });

        console.warn('--> the path to another-server is :' , another_server.path); // gives : /02/01/00
        const resolved_node = root_ca.resolve_path(another_server.path); // this gives : another_server
        const resolved_node2 = another_inte_ca.resolve_path(another_server.path); // this gives : another_server as well

        await fsPromises.writeFile('server2-cert.pem' , server2.cert);
        await fsPromises.writeFile('server2-key.pem' , server2.private_key);
        await fsPromises.writeFile('server2-bundle-pass11111.pfx' ,
            await server2.get_pkcs12('11111' , {legacy : true}));
        console.warn({server2});

        const revokee = root_ca.get_child({name : 'user1'});
        await fsPromises.writeFile('user1.pem' , revokee.cert);
        console.warn('revoke user' , revokee);
        await root_ca.revoke(revokee);
        const crl = await root_ca.get_crl();
        console.warn(crl.toString('utf8'));
        const info = await root_ca.get_crl_info();
        console.warn(info);

        console.warn('\n\nprinting root ca\n');
        console.warn(inspect(root_ca , {depth : null , colors : true}));
        console.warn('\n');

        try {
            console.warn('tryuing to get revokee cert');
            console.log(revokee.cert);
        } catch (err) {
            console.warn('... and we fail to get revokee cert, which was expected' , err);
        }
        // const found = root_ca.get_child({subject : 'CN=intermediate-ca'});
        // console.log({found});
        // await fsPromises.writeFile('server2.p12' ,
        //     await server2.get_pkcs12('12345' , {legacy : true})
        // );
    } catch (err) {
        console.warn('uncaught..' , err);
    }
})();
