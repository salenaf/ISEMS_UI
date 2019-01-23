/*
 * Страница управления правилами СОА
 *
 * Верися 0.1, дата релиза 26.07.2017
 * */

'use strict';

const async = require('async');

const writeLogFile = require('../../../libs/writeLogFile');

const informationUserGroupPermissions = require('../../../libs/informationUserGroupPermissions');
const informationForPageManagementIdsRules = require('../../../libs/management_settings/informationForPageManagementIdsRules');

module.exports = function(req, res, objHeader, socketIo) {
    async.parallel({
        //проверяем наличие прав у пользователя на работу с данной страницей
        userGroupPermissions: function(callback) {
            informationUserGroupPermissions(req, function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем информацию по правилам СОА
        mainInformation: function(callback) {
            informationForPageManagementIdsRules(function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, function(err, result) {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('menu/settings/setting_ids_rules', {});
        } else {
            //проверяем права на доступ к указанной директории
            let readStatus = result.userGroupPermissions.group_settings.management_ids_rules.element_settings.read.status;
            if (readStatus === false) return res.render('403');

            res.render('menu/settings/setting_ids_rules', {
                header: objHeader,
                userGroupPermissions: result.userGroupPermissions.group_settings.management_ids_rules.element_settings,
                mainInformation: result.mainInformation
            });
        }
    });
};