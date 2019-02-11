/**
 * Модуль генерации уникального идентификатора на основе переданной строки
 * 
 * Версия 0.1, дата релиза 11.02.2019
 */

'use strict';

const crypto = require('crypto');

module.exports.getSHA = (userString) => {
    return crypto.createHash('sha256').update(userString).digest('hex');
}

module.exports.getMD5 = (userString) => {
    return crypto.createHash('md5').update(userString).digest('hex');
}