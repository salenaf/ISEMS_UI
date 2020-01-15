/*
 * Страница управления правилами поиска
 *
 * Верися 0.1, дата релиза 27.07.2017
 * */

"use strict";

const async = require("async");

const writeLogFile = require("../../../libs/writeLogFile");

//const informationUserGroupPermissions = require('../../../libs/informationUserGroupPermissions');
//const informationForPageManagementIpsRules = require('../../../libs/management_settings/informationForPageManagementSources');

module.exports = function(req, res, objHeader) {
    async.parallel({
        test: function(callback) {
            callback(null, {});
        }
    }, function(err) {
        if (err) {
            writeLogFile("error", err.toString());
            res.render("menu/settings/setting_search_rules", {});
        } else {
            res.render("menu/settings/setting_search_rules", {
                header: objHeader
            });
        }
    });
};

/*
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
            /*informationForPageManagementIpsRules(function (err, result) {
             if(err) callback(err);
             else callback(null, result);
             });
            callback(null, {});
        }
    }, function(err, result) {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('menu/settings/setting_search_rules', {});
        } else {

            console.log(result);
            //проверяем права на доступ к указанной директории
            let readStatus = result.userGroupPermissions.group_settings.management_search_rules.element_settings.read.status;
            if (readStatus === false) return res.render('403');

            res.render('menu/settings/setting_search_rules', {
                header: objHeader,
                userGroupPermissions: result.userGroupPermissions.group_settings.management_search_rules.element_settings,
                mainInformation: result.mainInformation
            });
        }
    });
};*/