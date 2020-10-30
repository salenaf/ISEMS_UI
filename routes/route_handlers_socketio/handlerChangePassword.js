"use strict";

const crypto = require("crypto");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const hashPassword = require("../../libs/hashPassword");
const writeLogFile = require("../../libs/writeLogFile");
const informationAboutUser = require("../../libs/management_settings/informationAboutUser");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

/**
 * Модуль обработчик изменения пароля пользователя
 * 
 * @param {*} socketIo 
 */
module.exports = function(socketIo) {
    socketIo.on("change password", (data) => {
        changeUserPassword(data.arguments, socketIo, (err) => {
            if(err){
                writeLogFile("error", err.toString());

                if(err.name === "passwd management"){
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
        .then((authData) => {
            if (!authData.isAuthentication) {
                throw new MyError("passwd management", "Пользователь не авторизован.");
            }

            if (authData.document.userLogin !== data.user_login) {
                throw new MyError("passwd management", "Невозможно изменить пароль. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            //проверяем параметры полученные от пользователя
            if (!helpersFunc.checkUserSettingsManagementUsers(data)) {
                throw new MyError("passwd management", "Невозможно изменить пароль. Принятый от пользователя пароль некорректен.");
            }

            //проверяем является ли пользователь administrator, а пароль по умолчанию
            if((data.user_login === "administrator") && (data.user_password === "administrator")){
                throw new MyError("passwd management", "Невозможно изменить пароль. Принятый от пользователя пароль для пользователя 'administrator' является паролем 'по умолчанию'.");
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
        }).then((userID) => {
            let md5string = crypto.createHash("md5")
                .update(data.user_password)
                .digest("hex");

            //изменяем пароль по умолчанию для пользователя administrator
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelUser, {
                    id: userID,
                    update: {
                        date_change: +(new Date()),
                        password: hashPassword.getHashPassword(md5string, "isems-ui"),
                    },
                }, (err) => {
                    if (err) reject(err);
                    else resolve(null);
                });
            });
        }).then(() => {
            return new Promise((resolve, reject) => {
                require("../../libs/helpers/getSessionId")("socketIo", socketIo, (err, sessionId) => {
                    if (err) reject(err);
                    else resolve(sessionId);
                });
            });
        }).then((sessionID) => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, {
                    query: { session_id: sessionID },
                    select: { passport_id: 1 },
                }, (err, result) => {
                    if(err) reject(err);
                    else resolve(result.passport_id);
                });
            });
        }).then((passportID) => {
            //меняем параметр is_admin_password_default в коллекции passport_addition_information
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelAdditionalPassportInformation, {
                    query: { passport_id: passportID },
                    update: { is_admin_password_default: false },
                }, (err) => {
                    if (err) reject(err);
                    else resolve(null);
                });
            });
        }).then(() => {
            callback(null);
        }).catch((err) => {
            callback(err);
        });
}
