"use strict";

const models = require("../controllers/models");
const commons = require("../libs/helpers/commons");
const hashPassword = require("../libs/hashPassword");
const writeLogFile = require("../libs/writeLogFile");
const mongodbQueryProcessor = require("../middleware/mongodbQueryProcessor");

/**
 * Стратегия локальной аутентификации пользователей
 * 
 * @param{*} - login
 * @param{*} - password
 * @param{*} - cb
 */
exports.authenticate = function(login, password, cb) {
    let testLogin = commons.getRegularExpression("stringAlphaNumEng").test(login);
    let testPasswd = commons.getRegularExpression("stringPasswd").test(password);

    if(!testLogin || !testPasswd){
        return cb(null, false, { message: "incorrect username or password" });
    }

    mongodbQueryProcessor.querySelect(models.modelUser, { query: { login: login } },
        (err, user) => {
            if (err) return cb(null, false, { message: "incorrect username or password" });

            let hashPwd = hashPassword.getHashPassword(password, "isems-ui");

            if ((user === null) || (user.password !== hashPwd)) {
                return cb(null, false, { message: "incorrect username or password" });
            }

            //проверяем использует ли администратор дефолтный пароль
            let isDefaultPassword = ((login === "administrator") && (hashPwd === "2ab65043ba1e301ab163c6d336dd1469ea087016c52743c4d51ff2d6c0b1c8c1")) ? true : false;

            //записываем информацию о пользователе по его passport ID 
            require("../libs/mongodb_requests/passportAdditionInformation").create(login, user._id, isDefaultPassword, (err, obj) => {
                if (err) writeLogFile("error", err.toString());
                else writeLogFile("info", `authentication user name '${login}'`);

                cb(null, obj);
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