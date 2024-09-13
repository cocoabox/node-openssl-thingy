#!/usr/bin/env node

const {pki} = require('../lib');
const {PkiCA} = pki;
const fsPromises = require('node:fs').promises;

(async function () {
    const root_ca = new PkiCA();
    // write to disk whenever the Root CA updates
    root_ca.on('updated' , async ({why , now_firing , originates_from}) => {
        console.warn('... write to disk because' , (now_firing?.name ?? '(no name)') , why);
        await fsPromises.writeFile('root-ca.json' , root_ca.toString() , 'utf8');
    });

    console.warn('create root CA');
    await root_ca.create_cert({
        common_name : 'my_root_ca' ,
        alt_names : ['my-root-ca' , 'my-root-ca.local' , '*.my-root-ca.local'] ,
        days : 9999 ,
    });

    console.warn('create server');
    await root_ca.add_server({
        common_name : 'my_server' ,
        alt_names : ['my-server' , 'my-server.local' , '*.my-server.local'] ,
        days : 9999 ,
    });

    console.warn('create user');
    await root_ca.add_client({
        common_name : 'user1' ,
        email : 'user1@my_server' ,
        days : 9999 ,
    });

    console.warn('create intermediate CA');
    const inte_ca = await root_ca.add_ca({
        common_name : 'intermediate-ca' ,
        alt_names : ['inte-ca' , 'inte-ca.local' , '*.inte-ca.local'] ,
        days : 9999 ,
    });
    await fsPromises.writeFile('inte_ca.pem' , inte_ca.cert);

    console.warn('create server under intermediate CA');
    const server2 = await inte_ca.add_server({
        common_name : 'my_server2' ,
        alt_names : ['my-server2' , 'my-server2.local' , '*.my-server2.local'] ,
        days : 9999 ,
    });
    await fsPromises.writeFile('server2.pem' , server2.cert);
    console.warn({server2});

    const revokee = root_ca.get_child({name : 'user1'});
    await fsPromises.writeFile('user1.pem' , revokee.cert);
    console.warn('revoke user' , revokee);
    await root_ca.revoke(revokee);
    const crl = await root_ca.get_crl();
    console.warn(crl.toString('utf8'));
    const info = await root_ca.get_crl_info();
    console.warn(info);

    console.warn('printing root ca');
    console.warn(root_ca);

    try {
        console.warn('revokee cert?');
        console.log(revokee.cert);
    } catch (err) {
        console.warn('fail to get revokee cert' , err);
    }
    // const found = root_ca.get_child({subject : 'CN=intermediate-ca'});
    // console.log({found});
    // await fsPromises.writeFile('server2.p12' ,
    //     await server2.get_pkcs12('12345' , {legacy : true})
    // );

})();
