"use strict";

const async = require("async");

const globalObject = require("../../../configure/globalObject");
const writeLogFile = require("../../../libs/writeLogFile");
const checkAccessRightsPage = require("../../../libs/check/checkAccessRightsPage");

const MAX_CHUNK_LIMIT = 15;

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
            Promise.allSettled([
                new Promise((resolve, reject) => {
                    require("../../../middleware/mongodbQueryProcessor")
                        .queryCountAllDocument(require("../../../controllers/models")
                            .modelNotificationLogISEMSNIH, (err, countDocument) => {
                            if(err) reject(err);
                            else resolve({ reqType: "count", v: countDocument });
                        });
                }),
                new Promise((resolve, reject) => {
                    require("../../../middleware/mongodbQueryProcessor")
                        .querySelect(require("../../../controllers/models")
                            .modelNotificationLogISEMSNIH, {
                            isMany: true,
                            select: { 
                                _id: 0, 
                                __v: 0, 
                            },
                            options: {
                                sort: { date_register: "desc", test: -1 },
                                limit: MAX_CHUNK_LIMIT,
                            },
                        }, (err, documents) => {
                            if(err) reject(err);
                            else resolve({ reqType: "select", v: documents });
                        });
                }),
            ]).then((result) => {
                let objResult = {countDocument: 0, foundList: []};

                result.forEach((item) => {
                    if(item.status === "fulfilled"){
                        if(item.value.reqType === "count"){
                            objResult.countDocument = item.value.v;
                        }
                        if(item.value.reqType === "select"){
                            objResult.foundList = item.value.v;
                        }
                    }
                });

                callback(null, objResult);
            });
        },
        widgetsInformation: (callback) => {
            let numConnect = 0,
                numDisconnect = 0;

            let listSources = globalObject.getData("sources");
            for(let source in listSources){
                if(listSources[source].connectStatus){
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

        res.render("menu/network_interaction/page_notification_log", {
            header: objHeader,
            listItems: {
                connectionModules: {
                    moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
                },
                userPermissions: userPermissions.management_network_interaction.element_settings,
                mainInformation: result.mainInformation,
                maxChunkLimit: MAX_CHUNK_LIMIT,
                widgetsInformation: result.widgetsInformation,
                listSources: globalObject.getData("sources"),
            },
        });
    });
};