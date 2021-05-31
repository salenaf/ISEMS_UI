"use strict";

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

/**
 * Модуль обработчик запросов связанных с получения информации о
 * параметрах и состоянии источников (телеметрии)
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {
    const handlers = {
        "network interaction: get telemetry for list source": getTelemetryForListSource,
        "network interaction: get list source with deviation parameters": getListSourceDeviationParameters,
        "network interaction: delete information problem patameters": deleteInformationProblemPatameters,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function getTelemetryForListSource(socketIo, data) {
    let funcName = " (func 'getTelemetryForListSource')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            if ((typeof data.arguments === "undefined") || (typeof data.arguments.listSource === "undefined") || (data.arguments.listSource.length === 0)) {
                throw new MyError("management validation", "Приняты некорректные параметры запроса.");
            }

            return;
        }).then(() => {
            return require("../../libs/processing/route_socketio/sendCommandsModuleNetworkInteraction").managementTaskGetTelemetry(socketIo, data.arguments.listSource);
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else if (err.name === "management validation") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: `Запрос на получение телеметрии отклонен. ${err.message}`,
                });
            } else if (err.name === "management network interaction") {
                //при отсутствии доступа к модулю сетевого взаимодействия
                showNotify({
                    socketIo: socketIo,
                    type: "warning",
                    message: err.message.toString()
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });
            }

            writeLogFile("error", err.toString() + funcName);
        });
}

function getListSourceDeviationParameters(socketIo) {
    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            //получаем список источников у которых имеется отклонение параметров
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

            helpersFunc.sendBroadcastSocketIo(
                "module NI API", {
                    "type": "telemetryDeviationParameters",
                    "options": listSourceDeviationParameters,
                });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });
            }

            writeLogFile("error", err.toString() + " (func 'getListSourceDeviationParameters')");
        });
}

function deleteInformationProblemPatameters(socketIo, data) {
    console.log("func 'deleteInformationProblemPatameters', START...");
    console.log(data);

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {

            console.log("func 'deleteInformationProblemPatameters', processing...");

            if ((typeof data.arguments === "undefined") || (typeof data.arguments.sourceID === "undefined") || (isNaN(data.arguments.sourceID))) {
                throw new MyError("management validation", "Приняты некорректные параметры запроса.");
            }

            let sourceID = +data.arguments.sourceID;

            if (globalObject.deleteData("telemetrySources", sourceID)) {

                console.log("func 'deleteInformationProblemPatameters', deleted is OK!!!");

                helpersFunc.sendBroadcastSocketIo(
                    "module NI API", {
                        "type": "deletedTelemetryDeviationParameters",
                        "options": { sourceID: sourceID },
                    });
            }
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else if (err.name === "management validation") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: `Запрос на удаление информации отклонен. ${err.message}`,
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });
            }

            writeLogFile("error", err.toString() + " (func 'deleteInformationProblemPatameters')");
        });
}