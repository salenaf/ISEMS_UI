/**
 * Модуль предоставляющий сессионную информацию о пользователей
 * 
 * Версия 0.1, дата релиза 04.12.2019
 */

"use strict";

const models = require("../../controllers/models/");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function() {
    return new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, { isMany: true }, (err, sessions) => {
            if (err) reject(err);

            let listSession = {};

            sessions.forEach(element => {
                listSession[element.session_id] = {
                    userLogin: element.login,
                    userName: element.user_name,
                    userGroup: element.group_name,
                    groupSettings: element.group_settings,
                    userSettings: element.user_settings,
                };
            });

            resolve(listSession);
        });
    });
};