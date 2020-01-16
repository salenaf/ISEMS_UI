/*
 * Подготовка информации для вывода на странице settings_groups
 *
 * Версия 0.2, дата релиза 16.01.2020
 * */

"use strict";

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

module.exports = function(cb) {
    new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelGroup, {
            query: { group_name: "administrator" },
            select: { _id: 0, __v: 0, date_register: 0, group_name: 0, }
        }, (err, results) => {
            if (err) reject(err);
            else resolve((Object.keys(results.toObject())).filter(item => item !== "id"));
        });
    }).then((arrayNameItems) => {
        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.querySelect(models.modelGroup, { 
                isMany: true,
                select: { _id: 0, __v: 0, },
            }, (err, groups) => {
                if (err) return reject(err);

                let objGroup = {};

                for (let i = 0; i < groups.length; i++) {
                    objGroup[groups[i].group_name] = {
                        date_register: groups[i].date_register,
                        elements: {}
                    };

                    arrayNameItems.forEach(item => {
                        objGroup[groups[i].group_name].elements[item] = groups[i][item];
                    });
                }

                resolve(objGroup);
            });
        });
    }).then((objGroup) => {
        cb(null, objGroup);
    }).catch((err) => {
        cb(err);
    });
};