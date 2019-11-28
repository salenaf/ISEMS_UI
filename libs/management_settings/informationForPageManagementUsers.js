/*
 * Подготовка информации для вывода на странице settings_users
 *
 * Версия 0.1, дата релиза 28.11.2019
 * */

"use strict";

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(cb) {
    let objNameItems = {
        "date_register": "dateRegister",
        "date_change": "dateChange",
        "group": "group",
        "user_name": "userName",
        "login": "login"
    };

    mongodbQueryProcessor.querySelect(models.modelUser, { isMany: true }, (err, users) => {
        if (err) return cb(err);

        let objUsers = {};
        users.forEach(user => {
            objUsers[user.login] = {};
            for (let item in objNameItems) {
                objUsers[user.login][objNameItems[item]] = user[item];
            }
        });

        cb(null, objUsers);
    });
};