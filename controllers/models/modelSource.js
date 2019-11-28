/*
 * Описание модели источника
 *
 * Версия 0.1, дата релиза 10.01.2019
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

let sourcesSchema = new connection.Schema({
    id: { type: Number, index: true, unique: true },
    date_register: Number,
    date_change: Number,
    short_name: String,
    detailed_description: String,
    ipaddress: String,
    update_frequency: Number,
    range_monitored_addresses: [String]
});

module.exports = connection.model("sources", sourcesSchema);