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

    debug(`ALL COOKIE: ${objectSession.request.headers.cookie}`);

    //if (!(~objectSession.request.headers.cookie.indexOf(";"))) return callback(new Error("Error socketIo, incorrect cookie"));
    if (!objectSession.request.headers.cookie.includes(";")) return callback(new Error("Error socketIo, incorrect cookie"));
    let cookie = objectSession.request.headers.cookie.split("; ");

    let sessionId = "";
    for (let i = 0; i < cookie.length; i++) {
        if (cookie[i].includes("connect.sid")) {
            if (!cookie[i].includes(".")) return callback(new Error("Error socketIo, incorrect cookie"));
            sessionId = cookie[i].slice(16).split(".");
        }
    }

    debug(`session ID: ${sessionId}`);

    if (sessionId.length < 2) return callback(new Error("Error socketIo, incorrect cookie"));
    else callback(null, sessionId[0]);
}