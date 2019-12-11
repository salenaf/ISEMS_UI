/**
 * Модуль возвращает информацию о пользователе
 * 
 * Версия 0.1, дата релиза 05.12.2019
 */

"use strict";

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports.getInformationByLogin = function(userLogin, callback) {
    queryToDB({ login: userLogin }, (err, result) => {
        if (err) callback(err);
        else callback(null, result);
    });
};

module.exports.getInformationByID = function(userID, callback) {
    queryToDB({ user_id: userID }, (err, result) => {
        if (err) callback(err);
        else callback(null, result);
    });
};

function queryToDB(queryStr = {}, callback) {
    mongodbQueryProcessor.querySelect(models.modelUser, { query: queryStr }, (err, userInfo) => {
        if (err) callback(err);
        else callback(null, userInfo);
    });
}