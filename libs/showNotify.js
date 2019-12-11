/**
 * Модуль отправляющий пользователю информационное сообщение
 * 
 * Версия 0.1, дата релиза 10.12.2019
 */

"use strict";

const writeLogFile = require("./writeLogFile");

module.exports = function(settings) {
    let { socketIo = null, type = "danger", message = "сообщение не определено" } = settings;

    if (socketIo === null) return writeLogFile.writeLog("\tError: the 'socketIo' variable is not defined");

    socketIo.emit("notify information", {
        notify: JSON.stringify({ type: type, message: message })
    });
};