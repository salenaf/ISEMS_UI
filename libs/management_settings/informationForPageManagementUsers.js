/*
 * Подготовка информации для вывода на странице settings_users
 *
 * Версия 0.1, дата релиза 07.04.2017
 * */

'use strict';

const async = require('async');

const models = require('../../controllers/models');

module.exports = function (func) {
    let objNameItems = {
        'date_register': 'dateRegister',
        'date_change': 'dateChange',
        'group': 'group',
        'user_name': 'userName',
        'login': 'login'
    };

    models.modelUser.find(function (err, users) {
        if(err) return func(err);

        let objUser = {};
        for(let i = 0; i < users.length; i++){
            objUser[users[i].login] = {};
            for(let item in objNameItems){
                objUser[users[i].login][objNameItems[item]] = users[i][item];
            }
        }

        func(null, objUser);
    });
};
