"use strict";

const MyError = require("../libs/helpers/myError");
const helpersFunc = require("../libs/helpers/helpersFunc");
const globalObject = require("../configure/globalObject");

/**
 * Модуль автоматической генерации запросов к ISEMS-NIH 
 * 
 * @param {*} templateInfo - шаблон с информацией, на основе которого выполняется генерация запроса
 */
module.exports = function(templateInfo) {
    const templateRequest = {
        "telemetry": telemetryRequest,
        "filtration": filtrationRequest,
    };

    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            if (conn === null) {
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            return resolve(conn);
        });
    }).then((conn) => {
        return new Promise((resolve, reject) => {
            //нужно сравнить со списком в шаблоне и выбрать только подключенные
            let allSourceList = globalObject.getData("sources");
            let approvedSourceList = [];

            if (templateInfo.listSourceID.length === 0) {
                for (let sid in allSourceList) {
                    if (allSourceList[sid].connectStatus) {
                        approvedSourceList.push(+sid);
                    }
                }
            } else {
                //здесь сравнить наличие источников и их доступность
                templateInfo.listSourceID.forEach((item) => {
                    if ((typeof allSourceList[item] !== "undefined") && allSourceList[item].connectStatus) {
                        approvedSourceList.push(+item);
                    }

                    return false;
                });
            }

            if (approvedSourceList.length === 0) {
                return reject(new MyError("management sources connection", "Невозможно выполнить задачу, не один из источников не подключен."));
            }

            return resolve({ connect: conn, sourceList: approvedSourceList });
        });
    }).then(({ connect, sourceList }) => {
        templateRequest[templateInfo.taskType]({ connection: connect, sourceList: sourceList, parameters: templateInfo });
    }).catch((err) => {
        throw err;
    });
};

function telemetryRequest({ connection, sourceList, parameters = null }) {
    connection.sendMessage({
        msgType: "command",
        msgSection: "source control",
        msgInstruction: "give information about state of source",
        taskID: helpersFunc.getRandomHex(),
        options: {
            lsid: sourceList,
            ga: true, //запрос был сформирован автоматически
        },
    });
}

function filtrationRequest({ connection, sourceList, parameters }) {
    sourceList.forEach((sid) => {
        let currentTime = parameters.taskParameters.filtration.maxHour - parameters.taskParameters.filtration.minHour,
            timeBegin = parameters.dateTimeTrigger.full - ((parameters.taskParameters.filtration.minHour + currentTime) * 3600000),
            timeEnd = parameters.dateTimeTrigger.full - (parameters.taskParameters.filtration.minHour * 3600000);

        console.log(`timeBegin: '${timeBegin}' (${Math.trunc(timeBegin / 1000)})`);

        if (connection !== null) {
            connection.sendMessage({
                msgType: "command",
                msgSection: "filtration control",
                msgInstruction: "to start filtering",
                taskID: helpersFunc.getRandomHex(),
                options: {
                    id: sid,
                    un: "",
                    dt: {
                        s: Math.trunc(timeBegin / 1000),
                        e: Math.trunc(timeEnd / 1000),
                    },
                    p: parameters.taskParameters.filtration.networkProtocol,
                    f: parameters.taskParameters.filtration.inputValue,
                },
            });
        }
    });
}