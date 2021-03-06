"use strict";

const debug = require("debug")("getSessionId");
const globalObject = require("../../configure/globalObject");

/**
 * Получить ID сессии
 * 
 * @param{*} - typeSession
 * @param{*} - objectSession
 * @param{*} - callback
 */
module.exports = function(typeSession, objectSession, callback) {
    let objTypeSession = {
        //"http": getSessionForHttp,
        "socketIo": getSessionForSocketIo 
    };

    if (typeof objTypeSession[typeSession] === "undefined") return callback(new Error("uncertain type the name of the session"));

    objTypeSession[typeSession](objectSession, (err, sessionId) => {
        if (err) callback(err);
        else callback(null, sessionId);
    });
};

//function getSessionForHttp(objectSession, callback) {}

function getSessionForSocketIo(objectSession, callback) {
    if (typeof objectSession.request === "undefined") return callback(new Error("Error socketIo, incorrect request (func 'getSessionForSocketIo')"));
    if (typeof objectSession.request.headers === "undefined") return callback(new Error("Error socketIo,there is no title (func 'getSessionForSocketIo')"));
    if (typeof objectSession.request.headers.cookie === "undefined") return callback(new Error("Error socketIo, missing the cookie (func 'getSessionForSocketIo')"));

    let sessionId = "";
    let listSessionId = globalObject.getData("users");

    debug(listSessionId);

    for (let id in listSessionId) {
        if(id.length === 0){
            continue;
        }

        if(objectSession.request.headers.cookie.includes(id)) {
            sessionId = id;

            break;
        }
    }

    return (sessionId.length === 0) ? callback(new Error("Error socketIo, incorrect cookie (func 'getSessionForSocketIo')")) : callback(null, sessionId);
}