/*
 * Стратегия локальной аутентификации пользователей
 *
 * Версия 0.2, дата релиза 16.01.2019
 * */

"use strict";

const debug = require("debug")("authStrat");

const models = require("../controllers/models");
const hashPassword = require("../libs/hashPassword");
const writeLogFile = require("../libs/writeLogFile");
const mongodbQueryProcessor = require("../middleware/mongodbQueryProcessor");
const usersSessionInformation = require("../libs/mongodb_requests/usersSessionInformation");

exports.authenticate = function(userName, password, cb) {
    mongodbQueryProcessor.querySelect(models.modelUser, {
        query: { login: userName }
    }, (err, user) => {
        if (err) return cb(null, false, { message: "incorrect username or password" });

        let hashPwd = hashPassword.getHashPassword(password, "isems-ui");

        debug(userName);
        debug(password);

        if ((user === null) || (user.password !== hashPwd)) {
            return cb(null, false, { message: "incorrect username or password" });
        }

        //проверяем использует ли администратор дефолтный пароль
        let isDefaultPassword = ((userName === "administrator") && (hashPwd === "2ab65043ba1e301ab163c6d336dd1469ea087016c52743c4d51ff2d6c0b1c8c1")) ? true : false;

        debug(`userName: ${userName}`);
        debug(`current password: ${password}`);
        debug(`password after hex: ${hashPwd}`);
        debug(`found user: ${user}`);
        debug(`isDefaultPassword: ${isDefaultPassword}`);

        //добавляем информацию о пользователе (passport id) в sessions_user_information
        usersSessionInformation.create(userName, user._id, isDefaultPassword, err => {
            if (err) writeLogFile("error", err.toString());
            else writeLogFile("info", `authentication user name '${userName}'`);

            cb(null, {
                id: user._id,
                username: userName
            });
        });
    });
};

exports.serializeUser = function(user, cb) {
    cb(null, user.id);
};

exports.deserializeUser = function(id, cb) {
    mongodbQueryProcessor.querySelect(models.modelUser, { id: id }, (err, user) => {
        if ((user === null) || (user.id === null)) return cb(new Error("user.id in not found"));

        err ? cb(err) : cb(null, user.id);
    });
};