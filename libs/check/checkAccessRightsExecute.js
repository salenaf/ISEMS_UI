/*
* Проверка прав группы пользователей на выполнение заданных действий
*
* Версия 0.1, дата релиза 06.04.2017
* */

'use strict';

const models = require('../../controllers/models');

module.exports = function (obj, func) {
    models.modelSessionUserInformation.findOne({ session_id: obj.sessionId }, function (err, result) {
        if(err) return func(err, false);
        if(result === null) return func(new Error('not found info by a session ID'));

        let actionType = result.group_settings[obj.management].element_settings[obj.actionType].status;
        func(err, actionType);
    });
};