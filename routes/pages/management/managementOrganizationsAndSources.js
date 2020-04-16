"use strict";

const async = require("async");

const globalObject = require("../../../configure/globalObject");
const writeLogFile = require("../../../libs/writeLogFile");
const checkAccessRightsPage = require("../../../libs/check/checkAccessRightsPage");
const informationForPageManagementOrganizationAndSource = require("../../../libs/management_settings/informationForPageManagementOrganizationAndSource");

/**
 * Модуль формирующий страницу на которой реализовано управление сущностями (организациями, 
 * ее подразделениями и источниками)
 * 
 * @param {*} req
 * @param {*} res
 * @param {*} objHeader
 */ 
module.exports = function(req, res, objHeader) {
    async.parallel({
        permissions: (callback) => {
            checkAccessRightsPage(req, (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        mainInformation: (callback) => {
            informationForPageManagementOrganizationAndSource((err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        }
    }, (err, result) => {
        if (err) {
            writeLogFile("error", err.toString());
            
            res.render("menu/settings/setting_organizations_and_sources", {
                header: objHeader,
                userPermissions: {},
                mainInformation: {},
                listFieldActivity: globalObject.getData("commonSettings"),
            });
        
            return;
        }

        let userPermissions = result.permissions.group_settings;
        let readStatus = userPermissions.menu_items.element_settings.setting_organizations_and_sources.status;

        if (readStatus === false) return res.render("403");

        res.render("menu/settings/setting_organizations_and_sources", {
            header: objHeader,
            userPermissions: userPermissions.management_organizations_and_sources.element_settings,
            mainInformation: result.mainInformation,
            listFieldActivity: globalObject.getData("commonSettings", "listFieldActivity"),
        });
    });
};