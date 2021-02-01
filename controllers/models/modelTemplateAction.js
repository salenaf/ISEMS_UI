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
    },
    type: String,
    list_source_id: [Number],
    task_parameters: {
        filtration: {
            network_protocol: String,
            start_date: Number,
            end_date: Number,
            input_value: {
                ip: Array,
                pt: Array,
                nw: Array,
            }
        },
    },
});

module.exports = connection.model("template_actions", templateActionSchema);