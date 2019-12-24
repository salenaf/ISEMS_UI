/**
 * Модуль обработчик изменения пароля пользователя
 * 
 * Версия 0.1, дата релиза 25.12.2019
 */

"use strict";

const crypto = require("crypto");
const debug = require("debug")("handlerChangePassword");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const hashPassword = require("../../libs/hashPassword");
const writeLogFile = require("../../libs/writeLogFile");
const informationAboutUser = require("../../libs/management_settings/informationAboutUser");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

module.exports = function(socketIo) {
    socketIo.on("change password", data => {
        debug(data);

        changeUserPassword(data.arguments, socketIo, err => {
            if (err) {
                debug(err);

                writeLogFile("error", err.toString());

                if (err.name === "passwd management") {
                    return showNotify({
                        socketIo: socketIo,
                        type: "danger",
                        message: err.message
                    });
                }

                return showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });
            }

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Пароль пользователя с логином '${data.arguments.user_login}' был успешно изменен.`,
            });
        });
    });
};

function changeUserPassword(data, socketIo, callback) {
    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then(authData => {

            debug("авторизован ли пользователь");
            debug(authData);

            if (!authData.isAuthentication) {
                throw new MyError("passwd management", "Пользователь не авторизован.");
            }

            if (authData.document.userLogin !== data.user_login) {
                throw new MyError("passwd management", "Невозможно изменить пароль. Недостаточно прав на выполнение данного действия.");
            }

        }).then(() => {
            //проверяем параметры полученные от пользователя
            if (!helpersFunc.checkUserSettingsManagementUsers(data)) {
                throw new MyError("user management", "Невозможно изменить пароль. Принятый от пользователя пароль некорректен.");
            }
        }).then(() => {
            //ищем пользователя с заданным логином
            return new Promise((resolve, reject) => {
                informationAboutUser.getInformationByLogin(data.user_login, (err, userInfo) => {
                    if (err) return reject(err);

                    let myError = new MyError("user management", `Невозможно изменить пароль. Пользователя с логином '${data.user_login}' не существует.`);

                    if (userInfo === null) reject(myError);
                    else resolve(null, userInfo.id);
                });
            });
        }).then(userID => {
            let md5string = crypto.createHash("md5")
                .update(data.user_password)
                .digest("hex");

            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelUser, {
                    id: userID,
                    update: {
                        date_change: +(new Date()),
                        password: hashPassword.getHashPassword(md5string, "isems-ui"),
                    },
                }, err => {
                    if (err) reject(err);
                    else resolve(null);
                });
            });
        }).then(() => {
            callback(null);
        }).catch(err => {
            callback(err);
        });
}

/**
 *                 mongodbQueryProcessor.queryUpdate(models.modelUser, {
                    id: userInfo.id,
                    update: {
                        date_change: updateUser.dateChange,
                        password: hashPassword.getHashPassword(md5string, "isems-ui"),
                        group: updateUser.group,
                        user_name: updateUser.userName,
                        settings: {
                            sourceMainPage: []
                        },
                    },
                }, err => {
                    if (err) reject(err);
                    else resolve(updateUser);
                });
 */