"use strict";

const url = require("url");
const async = require("async");

const helpersFunc = require("../../../libs/helpers/helpersFunc");
const globalObject = require("../../../configure/globalObject");
const writeLogFile = require("../../../libs/writeLogFile");
const checkAccessRightsPage = require("../../../libs/check/checkAccessRightsPage");

/**
 * Модуль формирующий страницу статистики и аналитики
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

            callback(null, {});

        },
        widgetsInformation: (callback) => {
            let numConnect = 0,
                numDisconnect = 0;

            let listSources = globalObject.getData("sources");
            for (let source in listSources) {
                if (listSources[source].connectStatus) {
                    numConnect++;
                } else {
                    numDisconnect++;
                }
            }

            callback(null, {
                numConnect: numConnect,
                numDisconnect: numDisconnect,
            });
        }
    }, (err, result) => {
        if (err) {
            writeLogFile("error", err.toString());
            res.render("menu/network_interaction", {
                header: objHeader,
                userPermissions: {},
                mainInformation: {},
            });

            return;
        }

        let userPermissions = result.permissions.group_settings;
        let readStatus = userPermissions.menu_items.network_interaction.status;

        if (readStatus === false) return res.render("403");

        let urlQueryParameters = {};
        try {
            let validationRules = {
                taskID: "hexSumMD5",
                sourceID: "hostID",
                sourceName: "shortNameHost",
                taskBeginTime: "intervalTransmission",
            };

            (decodeURI(url.parse(req.originalUrl).query)).split("&").forEach((item) => {
                let tmpArray = item.split("=");
                if (tmpArray.length > 1) {
                    console.log(`Name: ${tmpArray[0]} - ${helpersFunc.checkInputValidation({ name: validationRules[tmpArray[0]], value: tmpArray[1] })} (${tmpArray[1]})`);

                    if (helpersFunc.checkInputValidation({ name: validationRules[tmpArray[0]], value: tmpArray[1] })) {
                        urlQueryParameters[tmpArray[0]] = tmpArray[1];
                    }
                }
            });
        } catch (err) {
            writeLogFile("error", err.toString());
        }

        res.render("menu/network_interaction/page_statistics_and_analytics_detal_task", {
            header: objHeader,
            listItems: {
                connectionModules: {
                    moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
                },
                userPermissions: userPermissions.management_network_interaction.element_settings,
                mainInformation: result.mainInformation,
                widgetsInformation: result.widgetsInformation,
                listSources: globalObject.getData("sources"),
                urlQueryParameters: urlQueryParameters,
            },
        });
    });
};