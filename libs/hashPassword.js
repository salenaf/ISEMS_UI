/*
 * Вывод хеша пароля
 *
 * Версия 0.1, дата релиза 29.03.2017
 * */

"use strict";

const crypto = require("crypto");

module.exports.getHashPassword = function(string, salt) {
    return crypto.createHash("sha256")
        .update(string)
        .update(salt)
        .digest("hex");
};