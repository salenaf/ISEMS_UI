/*
 * Описание модели шаблона повторяющегося действия
 *
 * Версия 0.1, дата релиза 19.01.2021
 * */

"use strict";

const globalObject = require("../../configure/globalObject");
const connection = globalObject.getData("descriptionDB", "MongoDB", "connection");

let templateActionSchema = new connection.Schema({
    template_id: { type: String, index: true, unique: true },
    user_name: String,
    time_creation: Number,
    date_time_trigger: {
        weekday: Object,
        hour: Number,
        minutes: Number,
        full: Number,
    },
    type: String,
    list_source_id: [Number],
    task_parameters: {
        filtration: {
            network_protocol: String,
            min_hour: Number,
            max_hour: Number,
            input_value: {
                ip: Object,
                pt: Object,
                nw: Object,
            }
        },
    },
});

module.exports = connection.model("template_actions", templateActionSchema);