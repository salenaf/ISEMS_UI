/*
 * Получаем дискриптор соединения с СУБД MongoDB
 *
 * Версия 0.1, дата релиза 05.12.2018
 * */

'use strict';

const mongoose = require('mongoose');

const config = require('../configure');

module.exports = function() {
    let username = config.get('mongoDB:user'),
        password = config.get('mongoDB:password'),
        host = config.get('mongoDB:host'),
        port = config.get('mongoDB:port');

    return mongoose.connect(`mongodb://${host}:${port}/isems-ui`, {
        useNewUrlParser: true,
        useFindAndModify: false,
        useCreateIndex: true,
        user: username,
        pass: password
    });
};