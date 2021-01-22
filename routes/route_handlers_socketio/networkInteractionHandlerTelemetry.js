"use strict";

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const getSessionId = require("../../libs/helpers/getSessionId");
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
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function getTelemetryForListSource(socketIo, data) {
    let funcName = " (func 'getTelemetryForListSource')";

    console.log("func 'getTelemetryForListSource'");
    console.log(data);

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

    console.log("func 'getListSourceDeviationParameters', START...");

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            //получаем список источников у которых имеется откланение параметров
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

            console.log(helpersFunc.sendBroadcastSocketIo(
                "module NI API", {
                    "type": "telemetryDeviationParameters",
                    "options": listSourceDeviationParameters,
                }));

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