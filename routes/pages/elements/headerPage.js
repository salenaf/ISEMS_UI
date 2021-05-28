"use strict";

const async = require("async");

const models = require("../../../controllers/models");
const globalObject = require("../../../configure/globalObject");
const usersSessionInformation = require("../../../libs/mongodb_requests/usersSessionInformation");

/**
 * Модуль формирующий информацию для заголовка страницы
 * 
 * @param{*} req
 */
module.exports = function(req) {
    return new Promise((resolve, reject) => {
        async.parallel({
            getPasswordInfo: (callback) => {
                require("../../../middleware/mongodbQueryProcessor").querySelect(models.modelAdditionalPassportInformation, {
                    query: { passport_id: req.session.passport.user }
                }, (err, result) => {
                    if (err) callback(err);
                    else callback(null, result);
                });
            },
            getSessionInfo: (callback) => {
                //получаем общую информацию о пользователе по его сессии
                usersSessionInformation.getInformation(req, (err, result) => {
                    if (err) callback(err);
                    else callback(null, result);
                });
            },
            restoreTmpModuleNetworkInteraction: (callback) => {
                //восстанавливаем свойство tmpModuleNetworkInteraction в globalObject

                if (!globalObject.hasData("tmpModuleNetworkInteraction", req.sessionID)) {
                    globalObject.setData("tmpModuleNetworkInteraction", req.sessionID, {
                        tasksDownloadFiles: {},
                        unresolvedTask: {},
                        resultFoundTasks: {},
                    });
                }

                callback(null);
            },
        }, (err, result) => {
            if (err) reject(err);

            let objMenuSettings = {};
            let createList = function(listMenu, items) {
                for (let key in items) {
                    if (typeof items[key].name === "undefined") {
                        if (items[key].status) {
                            listMenu[key] = { name: items[key].description, status: items[key].status };
                        }

                        continue;
                    }

                    listMenu[key] = { name: items[key].name, submenu: {} };

                    createList(listMenu[key].submenu, items[key]);
                }
            };

            let resolveObject = {
                login: "",
                userName: "",
                isPasswordDefaultAdministrator: false,
                connectionModules: {
                    moduleHAI: globalObject.getData("descriptionAPI",
                        "analyticalInformationManagement",
                        "connectionEstablished"), //модуль управления аналитической информацией
                    moduleMRSICT: globalObject.getData("descriptionAPI",
                        "managingRecordsStructuredInformationAboutComputerThreats",
                        "connectionEstablished"), //модуль управления записями структуированной информации о компьютерных угрозах
                    moduleNI: globalObject.getData(
                        "descriptionAPI", 
                        "networkInteraction", 
                        "connectionEstablished") //модуль сетевого взаимодействия
                },
                menuSettings: {}
            };

            try {
                let menuItems = result.getSessionInfo.group_settings.menu_items;
                createList(objMenuSettings, menuItems);

                resolveObject.login = result.getSessionInfo.login;
                resolveObject.userName = result.getSessionInfo.user_name;
                resolveObject.isPasswordDefaultAdministrator = result.getPasswordInfo.is_admin_password_default;
                resolveObject.menuSettings = objMenuSettings;

                resolve(resolveObject);
            } catch (err) {
                resolve(resolveObject);
            }
        });
    });
};