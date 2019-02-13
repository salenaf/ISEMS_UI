/*
 * Страница управления группами пользователей
 *
 * Верися 0.1, дата релиза 28.03.2017
 * */

'use strict';

const debug = require('debug')('managementGroups');

const async = require('async');

const writeLogFile = require('../../../libs/writeLogFile');
const checkAccessRightsPage = require('../../../libs/check/checkAccessRightsPage');
const informationForPageManagementGroups = require('../../../libs/management_settings/informationForPageManagementGroups');

module.exports = function(req, res, objHeader) {
    async.parallel({
        //проверяем наличие прав у пользователя на работу с данной страницей
        userGroupPermissions: callback => {
            checkAccessRightsPage(req, (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем информацию по группам
        mainInformation: callback => {
            informationForPageManagementGroups((err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, (err, result) => {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('menu/settings/setting_groups', {});

            return;
        }

        //проверяем права на доступ к странице
        let readStatus = result.userGroupPermissions.group_settings.menu_items.element_settings.setting_groups.status;
        if (readStatus === false) return res.render('403');

        let objResult = {
            header: objHeader,
            userGroupPermissions: result.userGroupPermissions.group_settings.management_groups.element_settings,
            mainInformation: result.mainInformation
        };

        debug(result.mainInformation.administrator);
        debug(objResult.userGroupPermissions);

        res.render('menu/settings/setting_groups', objResult);
    });
};