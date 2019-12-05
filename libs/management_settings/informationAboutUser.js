/**
 * Модуль возвращает информацию о пользователе по его логину
 * 
 * Версия 0.1, дата релиза 05.12.2019
 */

"use strict";

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(userLogin, callback) {
    new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelUser, { query: { login: userLogin } }, (err, userInfo) => {
            if (callback !== null) {
                if (err) callback(err);
                else callback(null, userInfo);
            } else {
                if (err) reject(err);
                else resolve(userInfo);
            }
        });
    });
};