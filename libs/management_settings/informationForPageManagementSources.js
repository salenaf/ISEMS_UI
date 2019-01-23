/*
* Подготовка информации по источникам
*
* Версия 0.1, дата релиза 11.04.2017
* */

'use strict';

const models = require('../../controllers/models');

module.exports = function (func) {
    models.modelSource.find({}, { date_register: 1, date_change: 1, id: 1, short_name: 1, _id: 0 }, function (err, result) {
        if(err) func(err);
        else func(null, result);
    }).sort({ id: 1 });
};