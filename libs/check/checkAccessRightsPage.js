/*
 * Информация о правах группы к которой относится пользователь
 *
 * Версия 0.2, дата релиза 20.04.2019
 * */

"use strict";

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(req, callback) {
    try {
        let passportId = req.user;

        mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, 
            { query: { passport_id: passportId, }}, 
            (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
    } catch(err){
        callback(err);
    }
};