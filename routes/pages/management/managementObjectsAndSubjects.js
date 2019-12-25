/*
 * Страница управления источниками
 *
 * Верися 0.1, дата релиза 28.03.2017
 * */

"use strict";

const async = require("async");

const writeLogFile = require("../../../libs/writeLogFile");

const informationUserGroupPermissions = require("../../../libs/informationUserGroupPermissions");
const informationForPageManagementSources = require("../../../libs/management_settings/informationForPageManagementSources");

module.exports = function(req, res, objHeader, socketIo) {
    res.render("menu/settings/setting_objects_and_subjects", {
        header: objHeader,
    });

    /*async.parallel({
        //проверяем наличие прав у пользователя на работу с данной страницей
        userGroupPermissions: function(callback) {
            informationUserGroupPermissions(req, function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        //получаем информацию по источникам
        mainInformation: function(callback) {
            informationForPageManagementSources(function(err, result) {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, function(err, result) {
        if (err) {
            writeLogFile("error", err.toString());
            res.render("menu/settings/setting_objects_and_subjects", {});
        } else {
            //проверяем права на доступ к указанной директории
            let readStatus = result.userGroupPermissions.group_settings.setting_objects_and_subjects.element_settings.read.status;
            if (readStatus === false) return res.render("403");

            res.render("menu/settings/setting_objects_and_subjects", {
                header: objHeader,
                userGroupPermissions: result.userGroupPermissions.group_settings.management_sources.element_settings,
                mainInformation: result.mainInformation
            });
        }
    });*/
};