"use strict";

const debug = require("debug")("niht");

//const models = require("../../controllers/models");
//const MyError = require("../../libs/helpers/myError");
//const showNotify = require("../../libs/showNotify");
//const helpersFunc = require("../../libs/helpers/helpersFunc");
//const writeLogFile = require("../../libs/writeLogFile");
//const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
//const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

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
    debug("func 'getTelemetryForListSource'");
    debug(data);
}