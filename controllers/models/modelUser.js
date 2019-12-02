/*
 * Описание модели пользователя
 *
 * Версия 0.1, дата релиза 10.01.2019
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

let usersSchema = new connection.Schema({
    user_id: String,
    date_register: Number,
    date_change: Number,
    login: String,
    password: String,
    group: String,
    user_name: String,
    settings: {
        sourceMainPage: Array
    }
});

module.exports = connection.model("users", usersSchema);