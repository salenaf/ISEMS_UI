/*
* Информация о правах группы к которой относится пользователь
*
* Версия 0.1, дата релиза 03.04.2017
* */

'use strict';

const models = require('../controllers/models');

module.exports = function (req, func) {
    models.modelSessionUserInformation.findOne({ session_id: req.sessionID }, function(err, groupData) {
        if(err) return func(new Error('the group model is not defined'));

        func(null, groupData);
    });
};