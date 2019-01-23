/*
 * Модуль формирующий информацию для заголовка страницы
 *
 * Версия 0.1, дата релиза 15.01.2019
 * */

'use strict';

const usersSessionInformation = require('../../../libs/mongodb_requests/usersSessionInformation');

module.exports = function(req, cb) {
    usersSessionInformation.getInformation({ sessionId: req.sessionID }, (err, result) => {
        if (err) return cb(err);

        let objMenuSettings = {};
        let menuItems = result.group_settings.menu_items;

        let createList = function(listMenu, items) {
            for (let key in items) {
                if (typeof items[key].name === 'undefined') {
                    if (items[key].status) {
                        listMenu[key] = { name: items[key].description, submenu: {} };
                    }

                    continue;
                }

                listMenu[key] = { name: items[key].name, submenu: {} };

                createList(listMenu[key].submenu, items[key]);
            }
        };

        createList(objMenuSettings, menuItems);

        cb(null, {
            login: result.login,
            userName: result.user_name,
            isPasswordDefaultAdministrator: result.isPasswordDefaultAdministrator,
            menuSettings: objMenuSettings
        });
    });
};