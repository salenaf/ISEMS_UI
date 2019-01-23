/*
 * Чтение настроек из конфигурационного файла config.json
 *
 * Версия 0.1, дата релиза 24.03.2017
 * */

'use strict';

let nconf = require('nconf');

nconf.argv()
    .env()
    .file({ file: './configure/config.json' });

module.exports = nconf;