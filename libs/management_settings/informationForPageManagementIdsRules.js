/*
* Подготовка информации для страницы управления правилами IDS
*
* Версия 0.1, дата релиза 17.08.2017
* */

"use strict";

const async = require("async");

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");


/// НЕ ТО!!!!!!!!!!!!!!
module.exports = function (callback) {
    async.parallel({
        //получаем доп. информацию о загруженных правилах
        additionalInformation: function (callback) {
            models.modelAdditionalInformation.find({}, { _id:0, ids_rules:1 }, (err, document) => {
                if(err) callback(err);
                else callback(null, document);
            });
        },
        //получаем список классов правил СОА
        listCountClassType: function (callbackParallel) {
            models.modelSOARules.aggregate([//modelRulesIDS
                { $group: {
                    _id: "$classType",
                    count: { $sum: 1 }
                }},
                { $sort: { count: -1 }}
            ], (err, document) => {
                if(err) callbackParallel(err);
                else callbackParallel(null, document);
            });
        }
    }, function (err, objResult) {
      
        if(err) callback(err);
        else callback(null, objResult);
    });
};