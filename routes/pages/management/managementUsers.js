/*
 * Страница управления пользователями
 *
 * Верися 0.1, дата релиза 28.03.2017
 * */

'use strict';

const async = require('async');

const writeLogFile = require('../../../libs/writeLogFile');

const informationItemGroups = require('../../../libs/management_settings/informationItemGroups');
const informationUserGroupPermissions = require('../../../libs/informationUserGroupPermissions');
const informationForPageManagementUsers = require('../../../libs/management_settings/informationForPageManagementUsers');

module.exports = function(req, res, objHeader, socketIo) {
    async.parallel({
        //проверяем наличие прав у пользователя на работу с данной страницей
        userGroupPermissions: function(callback) {
            informationUserGroupPermissions(req, function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем список групп
        getItemGroups: function(callback) {
            informationItemGroups(function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем информацию по пользователям
        mainInformation: function(callback) {
            informationForPageManagementUsers(function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, function(err, result) {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('menu/settings/setting_users', {});
        } else {
            //проверяем права на доступ к указанной директории
            let readStatus = result.userGroupPermissions.group_settings.management_users.element_settings.read.status;
            if (readStatus === false) return res.render('403');

            res.render('menu/settings/setting_users', {
                header: objHeader,
                userGroupPermissions: result.userGroupPermissions.group_settings.management_users.element_settings,
                itemGroups: result.getItemGroups,
                mainInformation: result.mainInformation
            });
        }
    });
};