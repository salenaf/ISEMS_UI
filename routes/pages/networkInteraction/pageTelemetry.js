"use strict";

const async = require("async");

const globalObject = require("../../../configure/globalObject");
const writeLogFile = require("../../../libs/writeLogFile");
const checkAccessRightsPage = require("../../../libs/check/checkAccessRightsPage");

/**
 * Модуль формирующий страницу с информацией о уже выполненных
 * задачах по фильтрации файлы по которым выгружены не были
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
            let listSourceDeviationParameters = [];
            let telemetrySources = globalObject.getData("telemetrySources");
            for (let sid in telemetrySources) {
                if (!telemetrySources[sid].deviationParametersSource) {
                    continue;
                }

                let sourceInfo = globalObject.getData("sources", sid);

                listSourceDeviationParameters.push({
                    sourceID: sid,
                    shortSourceName: (sourceInfo === null) ? "" : sourceInfo.shortName,
                    timeReceipt: telemetrySources[sid].timeReceipt,
                    telemetryParameters: telemetrySources[sid].telemetryParameters,
                });
            }

            callback(null, { listSourceDeviationParameters: listSourceDeviationParameters });
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

        res.render("menu/network_interaction/page_source_telemetry", {
            header: objHeader,
            listItems: {
                connectionModules: {
                    moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
                },
                userPermissions: userPermissions.management_network_interaction.element_settings,
                mainInformation: result.mainInformation,
                widgetsInformation: result.widgetsInformation,
                listSources: globalObject.getData("sources"),
            },
        });
    });
};