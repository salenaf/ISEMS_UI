"use strict";

const debug = require("debug")("niht");

//const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
//const helpersFunc = require("../../libs/helpers/helpersFunc");
const writeLogFile = require("../../libs/writeLogFile");
//const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
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

    debug("func 'getTelemetryForListSource'");
    debug(data);

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            let filtrTaskParametr = authData.document.groupSettings.management_network_interaction.element_settings.management_tasks_filter.element_settings;
            //может ли пользователь создавать задачи на фильтрацию
            if (!filtrTaskParametr.create.status) {
                throw new MyError("management auth", "Невозможно отправить запрос на фильтрацию. Недостаточно прав на выполнение данного действия.");
            }

            if ((typeof data.arguments === "undefined") || (typeof data.arguments.listSource === "undefined") || (data.arguments.listSource.length === 0)) {
                throw new MyError("management validation", "Приняты некорректные параметры запроса.");
            }

            return;
        }).then(() => {
            return require("../../libs/processing/route_socketio/sendCommandsModuleNetworkInteraction").managementTaskGetTelemetry(data.arguments.listSource);
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
                    message: `Задача по фильтрации отклонена. ${err.message}`,
                });
            } else if (err.name === "management network interaction") {
                //при отсутствии доступа к модулю сетевого взаимодействия
                showNotify({
                    socketIo: socketIo,
                    type: "warning",
                    message: err.message.toString()
                });
            } else {
                let msg = "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.";

                if ((err.message.toString()).includes("duplicate key")) {
                    msg = "Совпадение ключевых полей, запись в базу данных невозможен.";
                }

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });
            }

            writeLogFile("error", err.toString() + funcName);
        });
}