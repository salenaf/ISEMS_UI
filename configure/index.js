/*
 * Чтение настроек из конфигурационного файла config.json
 * */

"use strict";

let nconf = require("nconf");

nconf.argv()
    .env()
    .file({ file: `${__dirname}/config_1.json` });

module.exports = nconf;