"use strict";

const models = require("../../controllers/models");
const globalObject = require("../../configure/globalObject");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

/**
 * Формирует в globalObject список источников для контроля 
 * состояния их сетевого соединения 
 */
module.exports = function() {
    return new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelSourcesParameter, {
            isMany: true,
            select: { _id: 0, id: 1, source_id: 1, short_name: 1, description: 1 },
        }, (err, sources) => {
            if (err) reject(err);

            sources.forEach((item) => {
                globalObject.setData("sources", item.source_id, {
                    shortName: item.short_name,
                    description: item.description,
                    connectStatus: false,
                    connectTime: 0,
                    id: item.id,
                    appVersion: "",
                    appReleaseDate: 0,
                });
            });

            resolve();
        });
    });
};