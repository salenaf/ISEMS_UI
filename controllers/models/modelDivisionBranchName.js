/*
 * Описание модели названия подразделения или филиала организации
 *
 * Версия 0.1, дата релиза 15.01.2020
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

/**
 * id - уникальный идентификатор присваиваемый приложением
 * id_organization - уникальный идентификатор организации
 * date_register - дата и время регистрации источника
 * date_change - дата и время изменения информации об источнике
 * name - название филиала или подразделения организации
 * physical_address - физический адрес
 * description - дополнительное описание
 * source_list - уникальный идентификатор источника
*/
let usersSchema = new connection.Schema({
    id: { type: String, index: true, unique: true },
    id_organization: { type: String, index: true },
    date_register: Number,
    date_change: Number,    
    name: String,
    physical_address: String,
    description:String,
    source_list: [String],
});

module.exports = connection.model("division_branch_name", usersSchema);