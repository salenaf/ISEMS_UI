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

    console.log("func 'handlerAutomaticGenerationQueries', START");

    const templateRequest = {
        "telemetry": telemetryRequest,
        "filtration": filtrationRequest,
    };

    return new Promise((resolve, reject) => {
        process.nextTick(() => {

            console.log("func 'handlerAutomaticGenerationQueries, get connection with module'");

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            if (conn === null) {
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            return resolve(conn);
        });
    }).then((conn) => {
        return new Promise((resolve, reject) => {
            console.log("func 'handlerAutomaticGenerationQueries', get sources list");

            let allSourceList = globalObject.getData("sources");
            //нужно сравнить со списком в шаблоне и выбрать только подключенные

            let approvedSourceList = [];
            if (templateInfo.listSourceID.length === 0) {
                for (let sid in allSourceList) {
                    if (allSourceList[sid].connectStatus) {
                        approvedSourceList.push(sid);
                    }
                }
            } else {
                //здесь сравнить наличие источников и их доступность
                approvedSourceList = templateInfo.listSourceID.filter((item) => {
                    if (typeof allSourceList[item] !== "undefined") {
                        return typeof allSourceList[item].connectStatus;
                    }

                    return false;
                });
            }

            console.log("func 'handlerAutomaticGenerationQueries', ----------------");

            if (approvedSourceList.length === 0) {

                console.log("DDDDDDDDDDDDDDDDDD");

                return reject(new MyError("management sources connection", "Невозможно выполнить задачу, не один из источников не подключен."));
            }

            return resolve({ connect: conn, sourceList: approvedSourceList });
        });
    }).then(({ connect, approvedSourceList }) => {
        console.log("func 'handlerAutomaticGenerationQueries', send requests");
        console.log(approvedSourceList);

        templateRequest[templateInfo.taskType]({ connection: connect, sourceList: approvedSourceList });

        console.log("func 'handlerAutomaticGenerationQueries', ALL Promise were complete");
    }).catch((err) => {
        throw err;
    });
};

function telemetryRequest({ connection, sourceList, parameters = null }) {
    console.log("func 'telemetryRequest', START...");

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
    console.log("func 'filtrationRequest', START...");

    /**
     *         return Promise.all(approvedSourceList.map((item) => {
            return templateRequest[templateInfo.taskType]({ connection: connect, sourceList: approvedSourceList });
        }));
     */
}