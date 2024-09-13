const create_conf_data = require('./create-conf-data');

const utils = require('./utils');
create_conf_data.ensure_conf = utils.ensure_conf;
create_conf_data.get_subject = utils.get_subject;

create_conf_data.for_ca = require('./for/ca');
create_conf_data.for_ca_csr = require('./for/ca-csr');
create_conf_data.for_digital_signature = require('./for/digital-signature');
create_conf_data.for_server = require('./for/server');
create_conf_data.for_client = require('./for/client');
create_conf_data.for_ca_operations = require('./for/ca-operations');

module.exports = create_conf_data;
