/*
 * Описание модели источника
 *
 * Версия 0.1, дата релиза 10.01.2019
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

/**
 * id - уникальный идентификатор присваиваемый приложением
 * id_division - уникальный идентификатор филиала или подразделения организации
 * source_id - уникальный идентификатор источника
 * date_register - дата и время регистрации источника
 * date_change - дата и время изменения информации об источнике
 * short_name - краткое название источника,
 * network_settings - сетевые настройки для доступа к источнику
 * source_settings - настройки источника 
 *   type_architecture_client_server - тип клиент серверной архитектуры (источник работает в режиме клиент или сервер)
 *   transmission_telemetry - отправка телеметрии
 *   maximum_number_simultaneous_filtering_processes - максимальное количество одновременных процессов фильтрации
 *   type_channel_layer_protocol - тип протокола канального уровня
 *   list_directories_with_file_network_traffic - список директорий с файлами сетевого трафика
 * description - дополнительное описание
 * information_about_app - информация о приложении
 *   version - версия приложения
 *   date - дата создания
 */
let sourcesSchema = new connection.Schema({
    id: { type: String, index: true, unique: true },
    id_division: String,
    source_id: { type: Number, index: true, unique: true },
    date_register: Number,
    date_change: Number,
    short_name: String,
    network_settings: { ipaddress: String, port: Number, token_id: String },
    source_settings: {
        type_architecture_client_server: String,
        transmission_telemetry: Boolean,
        maximum_number_simultaneous_filtering_processes: Number,
        type_channel_layer_protocol: String,
        list_directories_with_file_network_traffic: [String],
    },
    description: String,
    information_about_app: {
        version: String,
        date: String,
    },
});

module.exports = connection.model("sources_parameter", sourcesSchema);