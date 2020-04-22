"use strict";

const async = require("async");

const writeLogFile = require("../../../libs/writeLogFile");
const checkAccessRightsPage = require("../../../libs/check/checkAccessRightsPage");
const informationForPageManagementGroups = require("../../../libs/management_settings/informationForPageManagementGroups");

/**
 * Модуль управления группами пользователей
 * 
 * @param {*} req 
 * @param {*} res 
 * @param {*} objHeader 
 */
module.exports = function(req, res, objHeader) {
    async.parallel({
        //проверяем наличие прав у пользователя на работу с данной страницей
        permissions: (callback) => {
            checkAccessRightsPage(req, (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем информацию по группам
        mainInformation: (callback) => {
            informationForPageManagementGroups((err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, (err, result) => {
        if (err) {
            writeLogFile("error", err.toString());
            res.render("menu/settings/setting_groups", {});

            return;
        }

        //проверяем права на доступ к странице
        let readStatus = result.permissions.group_settings.menu_items.element_settings.setting_groups.status;
        if (readStatus === false) return res.render("403");

        let objResult = {
            header: objHeader,
            userGroupPermissions: result.permissions.group_settings.management_groups.element_settings,
            mainInformation: result.mainInformation
        };

        res.render("menu/settings/setting_groups", objResult);
    });
};