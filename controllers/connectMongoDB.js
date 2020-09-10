/*
 * Получаем дискриптор соединения с СУБД MongoDB
 *
 * Версия 0.2, дата релиза 10.09.2020
 * */

"use strict";

const mongoose = require("mongoose");

const config = require("../configure");

module.exports = function() {
    let username = config.get("mongoDB:user"),
        password = config.get("mongoDB:password"),
        host = config.get("mongoDB:host"),
        port = config.get("mongoDB:port"),
        nameDB = config.get("mongoDB:nameDB");

    return mongoose.connect(`mongodb://${host}:${port}/${nameDB}`, {
        useNewUrlParser: true,
        useFindAndModify: false,
        useCreateIndex: true,
        useUnifiedTopology: true,
        user: username,
        pass: password
    });
};