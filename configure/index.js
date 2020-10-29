/*
 * Чтение настроек из конфигурационного файла config.json
 * */

"use strict";

let nconf = require("nconf");

nconf.argv()
    .env()
    .file({ file: `${__dirname}/config.json` });

module.exports = nconf;