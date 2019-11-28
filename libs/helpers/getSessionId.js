/*
 * Получаем идентификатор сессии из
 * - socketIo
 * - http request
 *
 * @param {*} typeSession - тип сессии
 * @param {*} objectSession - объект сессии
 * 
 * Версия 0.1, дата релиза 08.08.2017
 * */

"use strict";

const debug = require("debug")("getSessionId");

const globalObject = require("../../configure/globalObject");

module.exports = function(typeSession, objectSession, callback) {
    let objTypeSession = {
        "http": getSessionForHttp,
        "socketIo": getSessionForSocketIo
    };

    if (typeof objTypeSession[typeSession] === "undefined") return callback(new Error("uncertain type the name of the session"));

    objTypeSession[typeSession](objectSession, (err, sessionId) => {
        if (err) callback(err);
        else callback(null, sessionId);
    });
};

function getSessionForHttp(objectSession, callback) {

}

function getSessionForSocketIo(objectSession, callback) {
    if (typeof objectSession.request === "undefined") return callback(new Error("Error socketIo, incorrect request"));
    if (typeof objectSession.request.headers === "undefined") return callback(new Error("Error socketIo,there is no title"));
    if (typeof objectSession.request.headers.cookie === "undefined") return callback(new Error("Error socketIo, missing the cookie"));

    let sessionID = "";
    let listSessionID = globalObject.getData("users");

    for (let sID in listSessionID) {

        debug(`current session ID: ${sID}`);

        if (objectSession.request.headers.cookie.includes(sID)) {

            sessionID = sID;
            break;
        }
    }

    debug(`Session ID: ${sessionID}`);

    return (sessionID.length === 0) ? callback(new Error("Error socketIo, incorrect cookie")) : callback(null, sessionID);
}