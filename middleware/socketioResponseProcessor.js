/**
 * Модуль обработки событий содержащих ответы на запросы от UI
 * передоваемые через socketio
 * 
 * Версия 0.1, дата релиза 22.01.2019
 */

"use strict";

const debug = require("debug")("socketioResponseProcessor");

const globalObject = require("../configure/globalObject");
const writeLogFile = require("../libs/writeLogFile");

/**
 * @param {*} socketIo
 */
module.exports = function(socketIo) {
    const eventEmitter = globalObject.getEventSocketioResponse();

    eventEmitter.on("error", (err) => {
        debug("Error message");
        debug(err);

        writeLogFile("error", err.toString());
    });
};