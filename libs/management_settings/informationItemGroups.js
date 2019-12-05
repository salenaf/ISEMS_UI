/*
 * Получаем массив доступных групп пользователей
 *
 * Версия 1.1, дата релиза 05.12.2019
 * */

"use strict";

const models = require("../../controllers/models");

module.exports = function(callback) {
    return new Promise((resolve, reject) => {
        models.modelGroup.find(function(err, groups) {
            if (callback !== null) {
                if (err) callback(err);
                else callback(null, groups.map((item) => item.group_name));
            } else {
                if (err) reject(err);
                else resolve(groups.map((item) => item.group_name));
            }
        });
    });
};