/*
 * Описание модели названия организации
 *
 * Версия 0.1, дата релиза 15.01.2020
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

/**
 * id - уникальный идентификатор присваиваемый приложением
 * date_register - дата и время регистрации источника
 * date_change - дата и время изменения информации об источнике
 * name - название организации
 * legal_address - юридический адрес
 * field_activity - род деятельности
 * division_or_branch_list_id - уникальный идентификатор филиала или подразделения организации
*/
let usersSchema = new connection.Schema({
    id: { type: String, index: true, unique: true },
    date_register: Number,
    date_change: Number,    
    name: String,
    legal_address: String,
    field_activity: String,
    division_or_branch_list_id: [String],
});

module.exports = connection.model("organization_name", usersSchema);