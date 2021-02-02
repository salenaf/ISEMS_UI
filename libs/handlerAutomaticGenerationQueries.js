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
        templateRequest[templateInfo.taskType]({ connection: connect, sourceList: sourceList });
    }).catch((err) => {
        throw err;
    });
};

function telemetryRequest({ connection, sourceList, parameters = null }) {
    console.log("func 'telemetryRequest', START...");
    console.log(sourceList);

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
     *  Надо сделать обработчик
     * 
     * 
     *         return Promise.all(approvedSourceList.map((item) => {
            return templateRequest[templateInfo.taskType]({ connection: connect, sourceList: approvedSourceList });
        }));
     */
}