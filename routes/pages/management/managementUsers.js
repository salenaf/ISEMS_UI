/*
 * Страница управления пользователями
 *
 * Верися 0.1, дата релиза 28.11.2019
 * */

"use strict";

const debug = require("debug")("managementUsers");

const async = require("async");

const writeLogFile = require("../../../libs/writeLogFile");
const checkAccessRightsPage = require("../../../libs/check/checkAccessRightsPage");
const informationForPageManagementUsers = require("../../../libs/management_settings/informationForPageManagementUsers");
const informationForPageManagementGroups = require("../../../libs/management_settings/informationForPageManagementGroups");

//const informationItemGroups = require("../../../libs/management_settings/informationItemGroups");
//const informationUserGroupPermissions = require("../../../libs/informationUserGroupPermissions");


module.exports = function(req, res, objHeader) {

    debug("func 'managementUsers' START");

    async.parallel({
        //проверяем наличие прав у пользователя на работу с данной страницей
        userGroupPermissions: callback => {
            checkAccessRightsPage(req, (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем информацию по пользователям
        mainInformation: callback => {
            informationForPageManagementUsers((err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем список доступных рабочих групп
        listWorkGroup: callback => {
            informationForPageManagementGroups((err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, (err, result) => {
        if (err) {

            debug(`ERROR: ${err}`);

            writeLogFile("error", err.toString());
            res.render("menu/settings/setting_users", {});

            return;
        }

        //проверяем права на доступ к странице
        let readStatus = result.userGroupPermissions.group_settings.menu_items.element_settings.setting_users.status;
        if (readStatus === false) return res.render("403");

        debug("Page rendering is access!!!");

        let objResult = {
            header: objHeader,
            userGroupPermissions: result.userGroupPermissions.group_settings.management_groups.element_settings,
            mainInformation: result.mainInformation,
            listWorkGroup: Object.keys(result.listWorkGroup),
        };

        debug(result.mainInformation);
        debug(objResult.userGroupPermissions);
        debug(objResult.listWorkGroup);

        res.render("menu/settings/setting_users", objResult);
    });
};