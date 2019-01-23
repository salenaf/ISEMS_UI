/*
 * Страница управления группами пользователей
 *
 * Верися 0.1, дата релиза 28.03.2017
 * */

'use strict';

const debug = require('debug')('managementGroups');

const async = require('async');

const writeLogFile = require('../../../libs/writeLogFile');

const informationUserGroupPermissions = require('../../../libs/informationUserGroupPermissions');
const informationForPageManagementGroups = require('../../../libs/management_settings/informationForPageManagementGroups');

module.exports = function(req, res, objHeader, socketIo) {
    async.parallel({
        //проверяем наличие прав у пользователя на работу с данной страницей
        userGroupPermissions: function(callback) {
            informationUserGroupPermissions(req, function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем информацию по группам
        mainInformation: function(callback) {
            informationForPageManagementGroups(function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, function(err, result) {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('menu/settings/setting_groups', {});

            return;
        }

        debug(result);

        //проверяем права на доступ к указанной директории
        let readStatus = result.userGroupPermissions.group_settings.management_groups.element_settings.read.status;
        if (readStatus === false) return res.render('403');

        res.render('menu/settings/setting_groups', {
            header: objHeader,
            userGroupPermissions: result.userGroupPermissions.group_settings.management_groups.element_settings,
            mainInformation: result.mainInformation
        });
    });
};