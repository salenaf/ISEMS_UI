/*
 * Описание модели дополнительной информации по паспорт
 *
 * Версия 0.1, дата релиза 21.04.2020
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

/**
 * passport_id - уникальный идентификатор
 * login - имя пользователя
 * is_admin_password_default - пароль по умолчанию (только для администратора)
 */
let usersSchema = new connection.Schema({
    passport_id: { type: String, index: true, unique: true },
    login: String,
    is_admin_password_default: Boolean
});

module.exports = connection.model("passport_addition_information", usersSchema);