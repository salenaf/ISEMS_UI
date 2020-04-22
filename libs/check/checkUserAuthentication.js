/*
 * Проверка авторизации пользователя
 *
 * Версия 0.2, дата релиза 04.12.2019
 * */

"use strict";

const getSessionId = require("../helpers/getSessionId");
const globalObject = require("../../configure/globalObject");

module.exports = function(socketIo) {
    return new Promise((resolve, reject) => {
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        let userInfo = globalObject.getData("users", sessionId);

        return {
            isAuthentication: (typeof sessionId === "string"),
            document: userInfo,
        };
    });
};