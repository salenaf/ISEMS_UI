/*
* Добавляем информацию в объект objGlobal.sources.sourceAvailability
* для контроля доступности источников
*
* Версия 0.1, дата релиза 24.04.2017
* */

'use strict';

const models = require('../../controllers/models');
const objGlobals = require('../../configure/objGlobals');

module.exports = function (func) {
    models.modelSource.find({}, {
        id: 1,
        short_name: 1,
        detailed_description : 1,
        update_frequency: 1,
        _id: 0
    }, function (err, document) {
        if(err) return func(err);

        objGlobals.sources.sourceAvailability = {};
        document.forEach((item) => {
            objGlobals.sources.sourceAvailability[item.id] = {
                shortName: item.short_name,
                detailedDescription : item.detailed_description,
                updateFrequency: item.update_frequency,
                dateLastUpdate: null,
                statusOld: false,
                statusNew: false
            };
        });

        func(null);
    });
};