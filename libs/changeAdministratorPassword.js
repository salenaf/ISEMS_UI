"use strict";

const async = require("async");

const models = require("../controllers/models");
const hashPassword = require("./hashPassword");
const writeLogFile = require("./writeLogFile");

/**
 * Модуль проверяет является ли пользователь администратором использующем пароль по умолчанию
 * 
 * @param{*} - req
 * @param{*} -func
 */
module.exports = function (req, func) {
    models.modelSessionUserInformation.findOne({ session_id: req.sessionID }, {
        login: 1,
        isPasswordDefaultAdministrator: 1
    }, function (err, document) {
        if(err){
            writeLogFile("error", err.toString());

            return func({ type: "danger", message: "внутренняя ошибка сервера, невозможно сменить пароль пользователя 'administrator'", action: "" });
        }

        if(document.login !== "administrator") return func({ type: "warning", message: "текущий пользователь не является администратором", action: "" });
        if(!document.isPasswordDefaultAdministrator) return func({ type: "warning", message: "невозможно сменить пароль", action: "" });

        async.parallel([
            //меняем пароль пользователя
            function (callback) {
                models.modelUser.findOneAndUpdate({ login: document.login }, {
                    "date_change": +(new Date()),
                    "password": hashPassword.getHashPassword(req.body.password, "waterfall-ui")
                }, function (err) {
                    if(err) callback(err);
                    else callback(null);
                });
            },
            //меняем занчение session.user.informations.isPasswordDefaultAdministrator на false
            function (callback) {
                models.modelSessionUserInformation.findOneAndUpdate({ session_id: req.sessionID }, {
                    "isPasswordDefaultAdministrator": false
                }, function (err) {
                    if(err) callback(err);
                    else callback(null);
                });
            }
        ], function (err) {
            if(err){
                writeLogFile("error", err.toString());

                return func({ type: "danger", message: "внутренняя ошибка сервера, невозможно сменить пароль пользователя 'administrator'", action: "" });
            }

            writeLogFile("info", "the password of the user 'administrator' has been changed");
            func({ type: "success", message: "пароль для пользователя 'administrator' успешно изменен", action: "reload" });
        });
    });
};