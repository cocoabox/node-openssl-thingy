# openssl-utils

provides a set of nodejs wrappers and shit like that for the `openssl` command line app on ur computer.

| user level             | see section...      | means                                                                                                                                 | bring your own..                             |
|------------------------|---------------------|---------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| openssl guru 🌶️🌶️🌶️ | basic usage         | quite literally a `spawn()` wrapper for `openssl`                                                                                     | CA configuration, cert, keys, everything     |
| openssl semi-guru 🌶️  | advanced usage      | wraps some common openssl usage like csr sign, generate  keypairs                                                                     | (same)                                       | 
| dummies 🍼             | more advanced usage | manages all CA configuration, cert storage, key storage, database, revocation list for you; you just do `my_ca.create_server(..)` etc | file to store the Root CA in serialized form |

almost everything is implemented as `async function`, i.e. you need the `await` keyword to run it properly

## basic usage ️🌶️🌶️️🌶️️

the `openssl()` async function executes the `openssl` app on your computer. this `openssl()` is not aware of any
subcommands of openssl - it's quite literally a wrapper for `exec()`-ing the openssl app on your computer : you are
responsible for supplying all subcommands, arguments, files, etc.

```javascript
const {openssl} = require('./openssl');
const {stdout} = openssl('SUBCOMMAND' , {arg : value , ...});
```

`arg` and `value` are command line `-arg value` pairs. For example,

```javascript
// openssl crl -in /tmp/crl.pem -noout -nextupdate
const {stdout} = await openssl('crl' , {
        in : '/tmp/crl.pem' ,
        noout : true ,   // arg '-noout' must be defined like this noout:true 
        nextupdate : true , // arg '-nextupdate'
    } ,
    {stdout_encoding : 'utf8'}   // if you don't specify stdout_encoding, then stdout will be a Buffer
);
```

If your input file is in a Buffer, you can just pass it directly, like this:

```javascript
// openssl crl -in /tmp/crl.pem -noout -nextupdate
const fsPromises = require('node:fs').promises;
const crl_file_buffer = await fsPromises.readFile('/tmp/crl.pem');
const {stdout} = await openssl('crl' , {
        in : crl_file_buffer ,
        noout : true ,
        nextupdate : true ,
    } ,
    {stdout_encoding : 'utf8'}   // if you don't specify stdout_encoding, then stdout will be a Buffer
);
```

Similarly, to grab output files, you pass `Buffer` as the argument

```javascript 
const in_cert = await fsPromises.readFile('/tmp/cert.pem');
const {out} = await openssl('x509' , {
    in : in_cert ,
    out : Buffer , // output key "out" to correspond with the key specified in here
    outform : 'DER' ,
});
// out = Buffer instance
```

<details>
<summary>of course you can specify a full path to write to ...</summary>

```javascript 
const in_cert = await fsPromises.readFile('/tmp/cert.pem');
await openssl('x509' , {
    in : in_cert ,
    out : '/tmp/output-cer.der' ,   // gives:  -out /tmp/output-cer.der
    outform : 'DER' ,
});
```

</details>

To emit the output Buffer object to another key, instead of passing `Buffer`, pass `{custom_key:Buffer}`, like this:

```javascript 
const in_cert = await fsPromises.readFile('/tmp/cert.pem');
const {custom_out} = await openssl('x509' , {
    in : in_cert ,
    out : {custom_out : Buffer} ,
    outform : 'DER' ,
});
// custom_out = Buffer instance
```

## advanced usage 🌶️️

there are some goodies under openssl, for example async function `create_rsa_keypair()` that will
perform some daily openssl tasks.

```javascript
const {openssl} = require('./openssl');

const {private_key , public_key} = await openssl.create_rsa_keypair({bits : 4096});
// private_key = Buffer instance
// public_key = Buffer instance
```

the following functions are offered:

- `create_cert()`
- `create_csr()`
- `create_rsa_keypair()`
- `sign_csr()`
- `revoke_cert()`

some of these functions assume you have a configured CA (along with config file, database file, crlnumber file, etc).
in thesee case, all the elements of the configured CA must be present in order for the function to work.

**NOTE** the openssl goodies functions shown here are not aware of your local CA configuration. You must pass the CA
config
file every time when it's needed. These goodies functions do nothing except being an openssl-wrapper.

However, you don't need to keep your own config file; you can generate it on-the-fly using. You can do so by using the
`create_conf_data.for_*****` functions

```javascript
const {create_conf_data} = require('./openssl-utils');
```

for example, to sign a CSR, you need a fully-configured CA. assuming you have all the files (database file, serial file,
etc) ready, call `create_conf_data.for_ca_operations()` to generate a config file `Buffer`, which you can then pass to
`openssl.sign_csr()`.

```javascript
const {create_conf_data , openssl} = require('./openssl-utils');
const ca_config = create_conf_data.for_ca_operations({
    serial : '/tmp/test_ca/serial' ,
    database : '/tmp/test_ca/database' ,
    crlnumber : '/tmp/test_ca/crlnumber' ,
    new_certs_dir : '/tmp/test_ca/new_certs_dir/' ,
});
const cert_buffer = await openssl.sign_csr({
    ca_config ,
    ca_cert : await fsPromises.readFile('/tmp/test_ca/ca-cert.pem') ,
    ca_private_key : await fsPromises.readFile('/tmp/test_ca/ca-key.pem') ,
    csr : await fsPromises.readFile('/tmp/csr-file.pem') ,
    days : 9999 ,
});
```

<details>
<summary>for more advanced usage of create_conf_data()...</summary>

the `create_conf_data()` function converts a javascript object into an INI file (openssl config file) and returns
its `Buffer`
representation so you can pass it to `openssl()`. Call `create_conf_data()` directly to create your own config file:

```javascript 
const {create_conf_data} = require('./openssl-utils');
conf_data_buffer = create_conf_data({
    section : {
        key : 'value' ,
        another_key : 'another_value' ,
        comma_separated_key_example : ['spam' , 'ham' , 'egg'] , // gives: comma_separated_key_example = spam,ham,egg
    }
});
```

</details>

note that openssl goodies functions such as `sign_csr()` can be called with kwarg-style calling. consider the
function signature:

```javascript
async function sign_csr(csr , ca_config , ca_cert , ca_private_key , {ca_private_key_password , days} = {}) {
    //
}
```

this can be called like this

```javascript
openssl.sign_csr(csr_buffer , ca_config_buffer , ca_cert_buffer , ... , {days : 9999});
```

or to increase readbility,

```javascript
openssl.sign_csr({csr : csr_buffer , ca_config : ca_config_buffer , ca_cert : ca_cert_buffer , ... , days : 9999});
```

## more advanced usage 🍼

a mini programamble cert authority, called `PkiCA` is provided for all your home cert authority needs. It has built-in
config management (takes care of all your CRL, OpenSSL database files, and crap like that), is easily serializable, and
can be hierarical.

```javascript
const {pki} = require('./openssl-utils');
const {PkiCA} = pki;
```

**NOTE** the `PkiCA` works solely in-memory, it is not aware of any file on your disk. It requires the temp directory
from time to time
when it performs certain operations but it's transient: the temp directory gets deleted right away. Everything stays in
memory.

Persistence can be achieved by serializing to and deserializing from JSON files (see `easily serializable` below). You
are
responsible for saving the JSON file to disk (and maybe compressing it) and reading it from disk.

### Features & Examples

- built in config management
  ```javascript
  const root_ca = new PkiCA();  
  const crl_buffer = await root_ca.get_crl(); // to get the CRL file ; if it's not there it'll be generated; it'll be cached automatically
  const intermediate_ca = await root_ca.add_ca({common_name: 'my-ca'}); // creates an intermediate CA, creates the key-pair and cert, and signs the cert
  const int_ca_cert_buffer = intermediate_ca.cert;
  const int_ca_cert_chain_buffer = intermediate_ca.cert_chain; 
  ```
    - no need to sign CSR; you get the signed cert and key right away
      ```javascript
      const root_ca = new PkiCA(); // this creates the root CA's keypair and cert right away
      const server = await root_ca.add_server({common_name : 'server1'}); // this creates server.csr internally, and signs it using the root CA's key right away
      const server_cert = server.cert; // the server's signed cert and key are immediately available to you
      const server_cert_chain = server.cert_chain; // signed cert chain
      const server_key = server.privateKey;  
      ```

    - revocation is easy
      ```javascript
      const root_ca = new PkiCA(); // this creates the root CA's keypair and cert right away
      const server = await root_ca.add_server({common_name : 'server1'}); // this creates server.csr internally, and signs it using the root CA's key right away
      const server_cert = server.cert; // get the server cert
      await root_ca.revoke(server); // to invalidate the server's cert
      const crl = await root_ca.get_crl(); // gets the CRL PEM file so you can distribute it on your server etc
      const is_revoked = server.isRevoked; // gives : true
      try {
          const tried_to_get_cert = root_ca.cert; // this raises : {revoked:true}
      }
      catch (error) { 
          // error is {revoked:true}
      }
      ```

- easily serializable
  ```javascript
  const root_ca = new PkiCA();  
  const json_str = root_ca.toString();
  // deserialize and recreate the CA object in memory
  const ca = PkiCA.fromJSON(json_str);
  // make use of the "updated" event to write only when there's change made to the CA
  // this event fires also if any child or grandchild is updated
  // to avoid writing too freequently, you can set a spring-load timer, but that's up to you
  root_ca.on('updated', async ()=>{
    await fs.promises.writeFile('/tmp/my-root-ca.json', root_ca.toString(), 'utf8');
  });
  ```

- hierarical
  ```javascript
  const root_ca = new PkiCA();
  const int_ca = await root_ca.add_ca({common_name : 'my_intermediate_ca'});
  const int_ca_2 = await int_ca.add_ca({common_name : 'my_intermediate_ca_2'});
  const server = await int_ca_2.add_server({common_name : 'my_server'});
  
  const gives_you_the_same_sever = root_ca.get_child({name : 'my_intermediate_ca'}) // the subject's common_name becomse int_ca.name
      .get_child({name : 'my_intermediate_ca_2'})
      .get_child({subject:'CN=my_server'}); // or {subject:{CN:'my_server}}
  ``` 
  and if you serialize `root_ca`, you get to save everything under it.

  **NOTE** the `.get_child()` method, when it receives a STRING or NUMBER, assumes it is the _SERIAL NUMBER_
  of the child member. to find a child with common name, pass instead:

    - `ca.get_child({name : 'COMMON_NAME_WANTED'})`
    - `ca.get_child({subject : {CN:'COMMON_NAME_WANTED'}})`
    - `ca.get_child({subject : 'CN=COMMON_NAME_WANTED'})`

  to find the first matching child with multiple subject fields,

    - `ca.get_child({subject : {CN:'COMMON_NAME_WANTED', C:'United States'}})` .. order is not important
    - `ca.get_child({subject : 'CN=COMMON_NAME_WANTED/C=United States')`      .. same as above

see `try-pki` for an example.

### word of caution

- performance

  for I/O performance, dont serialize into JSON string; the `.toJSON()` method returns a serialization-safe JSON object;
  use `MessagePack` or things like to store it to disk in an efficient manner.

- security

  if you serialize your `PkiCA` object and write it to disk, you are responsible for securing that file on disk! set
  tight permission like `rw-------` to the file, use S3 and set permissions, whatever you learned on your first day as
  an admin!

