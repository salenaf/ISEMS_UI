/**
 * Модуль отправляющий пользователю информационное сообщение
 * 
 * Версия 0.1, дата релиза 10.12.2019
 */

"use strict";

const getMD5 = require("./helpers/createUniqID").getMD5;
const writeLogFile = require("./writeLogFile");

module.exports = function(settings) {
    let { socketIo = null, type = "danger", message = "сообщение не определено" } = settings;

    if (socketIo === null) return writeLogFile.writeLog("\tError: the 'socketIo' variable is not defined");
    socketIo.emit("notify information", {
        notify: JSON.stringify({
            id: getMD5(`${+new Date()}_${randomInteger(1,1000)}`),
            type: type,
            message: message,
        })
    });
};

function randomInteger(min, max) {
    return Math.round((min - 0.5 + Math.random() * (max - min + 1)));
}