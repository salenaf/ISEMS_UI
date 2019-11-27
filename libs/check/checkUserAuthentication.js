/*
 * Проверка авторизации пользователя
 *
 * Версия 0.1, дата релиза 14.02.2019
 * */

"use strict";

const models = require("../../controllers/models");
const getSessionId = require("../helpers/getSessionId");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(socketIo) {
    return new Promise((resolve, reject) => {
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);

            mongodbQueryProcessor.querySelect(
                models.modelSessionUserInformation, { query: { session_id: sessionId } },
                (err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
        });
    }).then(result => {
        return {
            isAuthentication: result === null,
            document: result
        };
    }).catch(err => {
        console.log(err);
    });
};