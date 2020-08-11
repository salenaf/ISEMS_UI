/*
 * Описание модели журнала для хранения сообщений (notification message)
 * получаемых от модуля ISEMS-NIH
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

/**
 * id: уникальный идентификатор задачи
 * date_register: дата и время регистрации сообщения
 * type: тип сообщения (info, success, warning, danger) 
 * source_id: список ID источников
 * message: описание выполненного действия
*/
let notificationLog = new connection.Schema({
    id: { type: String, index: true },
    date_register: { type: Number, index: true },
    type: String,
    source_id: [],
    message: String,
});

module.exports = connection.model("notification_log_isems.nih", notificationLog);