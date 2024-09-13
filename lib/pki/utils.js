const {spawn} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function get_temp_path() {
    return path.join(os.tmpdir() , `openssl_temp_${Date.now()}_${Math.random()}`);
}

async function write_temp_file(buffer , opt) {
    const temp_path = get_temp_path();
    await fs.promises.writeFile(temp_path , buffer , opt);
    return temp_path;
}

module.exports = {write_temp_file};
