/*
 * Подготовка информации для вывода на странице setting_organizations_and_sources
 *
 * Версия 0.1, дата релиза 23.03.2020
 * */

"use strict";

const async = require("async");

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(callback) {
    async.parallel({
        shortListSource: (callbackParallel) => {
            mongodbQueryProcessor.querySelect(
                models.modelSourcesParameter, { 
                    isMany: true,
                    select: { 
                        _id: 0, 
                        __v: 0, 
                        description: 0,
                        date_change: 0, 
                        source_settings : 0, 
                        network_settings: 0,
                    },
                }, (err, list) => {
                    if(err) callbackParallel(err);
                    else callbackParallel(null, list);
                });
        },
        shortListDivision: (callbackParallel) => {
            mongodbQueryProcessor.querySelect(
                models.modelDivisionBranchName, { 
                    isMany: true,
                    select: { 
                        _id: 0, 
                        __v: 0, 
                        description: 0,
                        date_change:0,
                        date_register: 0, 
                        physical_address: 0,
                    },
                }, (err, list) => {
                    if(err) callbackParallel(err);
                    else callbackParallel(null, list);
                });
        },
        shortListOrganization: (callbackParallel) => {
            mongodbQueryProcessor.querySelect(
                models.modelOrganizationName, { 
                    isMany: true,
                    select: { 
                        _id: 0,
                        __v: 0, 
                        date_change:0,
                        date_register: 0, 
                        legal_address: 0,
                    },
                }, (err, list) => {
                    if(err) callbackParallel(err);
                    else callbackParallel(null, list);
                });
        },
    }, (err, listEntity) => {
        if (err) callback(err);
        else callback(null, listEntity);
    });
};