/*
 * Описание модели (ids.rules)
 * хранятся сигнатуры IDS
 *
 * Версия 0.1, дата релиза 10.01.2019
 * */

'use strict';

const globalObject = require('../../configure/globalObject');
const connection = globalObject.getData('descriptionDB', 'MongoDB', 'connection');

let idsRules = new connection.Schema({
    sid: { type: Number, index: true, unique: true },
    classType: { type: String, index: true },
    msg: String,
    body: String
}, { autoIndex: true });

module.exports = connection.model('ids.rules', idsRules);