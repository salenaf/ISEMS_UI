/*
 * Получаем массив доступных групп пользователей
 *
 * Версия 0.1, дата релиза 07.04.2017
 * */

"use strict";

const models = require("../../controllers/models");

module.exports = function(func) {
    models.modelGroup.find(function(err, groups) {
        if (err) return func(err);

        func(null, groups.map((item) => item.group_name));
    });
};