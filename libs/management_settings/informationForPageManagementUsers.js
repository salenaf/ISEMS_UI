/*
 * Подготовка списка пользователей для вывода на странице settings_users
 *
 * Версия 0.1, дата релиза 28.11.2019
 * */

"use strict";

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(callback) {
    let objNameItems = {
        "user_id": "userID",
        "date_register": "dateRegister",
        "date_change": "dateChange",
        "group": "group",
        "user_name": "userName",
        "login": "login"
    };

    mongodbQueryProcessor.querySelect(models.modelUser, { isMany: true }, (err, users) => {
        if (err) return callback(err);

        let listUsers = users.map(user => {
            let obj = {};
            for (let item in objNameItems) {
                obj[objNameItems[item]] = user[item];
            }

            return obj;
        });

        callback(null, listUsers);
    });
};