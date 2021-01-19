"use strict";

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
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