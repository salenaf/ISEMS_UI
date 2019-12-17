/**
 * Модуль обработчик дейсвий над пользователями
 * 
 * Версия 0.2, дата релиза 10.12.2019
 */

"use strict";

const async = require("async");
const crypto = require("crypto");

const debug = require("debug")("handlerActionsUsers");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const commons = require("../../libs/helpers/commons");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const hashPassword = require("../../libs/hashPassword");
const createUniqID = require("../../libs/helpers/createUniqID");
const writeLogFile = require("../../libs/writeLogFile");
const informationAboutUser = require("../../libs/management_settings/informationAboutUser");
const informationItemGroups = require("../../libs/management_settings/informationItemGroups");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

module.exports.addHandlers = function(socketIo) {
    const handlers = {
        "add new user": addUser,
        "update user": updateUser,
        "delete user": deleteUser,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function addUser(socketIo, data) {
    debug("reseived command 'add new user'");
    debug(data);

    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then(authData => {

            debug("авторизован ли пользователь");
            debug(authData);

            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("user management", "Пользователь не авторизован.");
            }

            debug("может ли пользователь создавать нового пользователя");

            //может ли пользователь создавать нового пользователя
            if (!authData.document.groupSettings.management_users.element_settings.create.status) {
                throw new MyError("user management", "Невозможно добавить нового пользователя. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            debug("Проверка прав пользователей выполненна успешно");

            //проверяем параметры полученные от пользователя
            if (!helpersFunc.checkUserSettingsManagementUsers(data.arguments)) {
                throw new MyError("user management", "Невозможно добавить нового пользователя. Один или более заданных параметров некорректен.");
            }
        }).then(() => {
            debug("Проверка параметров заданных пользователем выполненна успешно");

            return new Promise((resolve, reject) => {
                async.parallel({
                    listGroup: (callbackParallel) => {

                        debug("//проверяем наличие группы ");

                        //проверяем наличие группы 
                        informationItemGroups((err, listGroup) => {
                            if (err) return callbackParallel(err);

                            let errorMsg = `Невозможно добавить нового пользователя. Группы '${data.arguments.work_group}' не существует.`;
                            let myError = new MyError("user management", errorMsg);

                            if (!listGroup.some(elem => elem === data.arguments.work_group)) callbackParallel(myError);
                            else callbackParallel(null);
                        });
                    },
                    userInfo: (callbackParallel) => {

                        debug("//проверяем есть ли уже пользователь с таким логином");

                        //проверяем есть ли уже пользователь с таким логином 
                        informationAboutUser.getInformationByLogin(data.arguments.user_login, (err, userInfo) => {
                            if (err) return callbackParallel(err);

                            let errorMsg = `Невозможно добавить нового пользователя. Пользователь с логином '${data.arguments.user_login}' уже существует.`;
                            let myError = new MyError("user management", errorMsg);

                            if (userInfo !== null) callbackParallel(myError);
                            else callbackParallel(null);
                        });
                    }
                }, err => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }).then(() => {
            debug("Проверка наличия указанной группы и отсутствия такого же логина пользователя выполнена успешно");

            return new Promise((resolve, reject) => {

                debug("добавляем нового пользователя и пароль");
                debug(data.arguments.user_password);

                let md5string = crypto.createHash("md5")
                    .update(data.arguments.user_password)
                    .digest("hex");

                let newUser = {
                    userID: createUniqID.getMD5(`user_name_${data.arguments.user_login}`),
                    dateRegister: +(new Date()),
                    dateChange: +(new Date()),
                    login: data.arguments.user_login.toLowerCase(),
                    userName: data.arguments.user_name,
                    group: data.arguments.work_group,
                };

                mongodbQueryProcessor.queryCreate(models.modelUser, {
                    document: {
                        user_id: newUser.userID,
                        date_register: newUser.dateRegister,
                        date_change: newUser.dateChange,
                        login: newUser.login,
                        password: hashPassword.getHashPassword(md5string, "isems-ui"),
                        group: newUser.group,
                        user_name: newUser.userName,
                        settings: {
                            sourceMainPage: []
                        }
                    }
                }, err => {
                    if (err) reject(err);
                    else resolve(newUser);
                });
            });
        }).then(newUser => {

            debug("Отправляем полученный список в UI");

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Пользователь успешно добавлен"
            });

            socketIo.emit("add new user", JSON.stringify(newUser));

        }).catch(err => {

            debug(err);

            if (err.name === "user management") return showNotify({
                socketIo: socketIo,
                type: "danger",
                message: err.message
            });

            showNotify({
                socketIo: socketIo,
                type: "danger",
                message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору"
            });

            writeLogFile("error", err.toString());
        });
}

function updateUser(socketIo, data) {
    debug("-------- user edit -------");
    debug(data);

    /**
     * 
     * Сделать обработку изменения параметров пользователя!!!
     * Сделать модальное окно по изменению дефолтного пароля администратора
     * оно будет вызываться в разделе меню
     * 
     */

}

function deleteUser(socketIo, data) {
    let getUserInformation = informationAboutUser.getInformationByID.bind(null);

    debug(getUserInformation);

    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then(authData => {

            debug("авторизован ли пользователь");
            debug(authData);

            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("user management", "Пользователь не авторизован.");
            }

            debug("может ли пользователь удалять пользователя");

            //может ли пользователь создавать нового пользователя
            if (!authData.document.groupSettings.management_users.element_settings.delete.status) {
                throw new MyError("user management", "Невозможно удалить пользователя. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            debug("Проверка прав пользователей выполненна успешно");

            //проверяем параметры полученные от пользователя
            let pattern = commons.getRegularExpression("hexSumMD5");
            if (!pattern.test(data.arguments.userID)) {
                throw new MyError("user management", "Невозможно удалить пользователя. Получен не верный идентификатор.");
            }
        }).then(() => {
            return new Promise((resolve, reject) => {
                informationAboutUser.getInformationByID(data.arguments.userID, (err, userInfo) => {
                    if (err) reject(err);
                    else resolve(userInfo);
                });
            });
        }).then(userInfo => {
            debug("Ищем пользователя с указанным ID и проверяем есть ли он и его логин не 'Administrator'");
            debug(userInfo);

            if (userInfo === null || (typeof userInfo === "undefined")) {
                throw new MyError("user management", "Невозможно удалить пользователя, не найден пользователь с заданным идентификатором.");
            }

            if (userInfo.login === "administrator") {
                throw new MyError("user management", "Невозможно удалить пользователя, так как пользователь является администратором.");
            }

        }).then(() => {
            debug("Удаляем пользователя из таблицы БД");

            new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryDelete(require("../../controllers/models").modelUser, { query: { user_id: data.arguments.userID } }, err => {
                    if (err) reject(err);
                    resolve();
                });
            });
        }).then(() => {
            debug("Удаление пользователя выполненно успешно, отправляем сообщение об удалении в UI");

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Пользователь успешно удален"
            });

            socketIo.emit("del selected user", JSON.stringify({ userID: data.arguments.userID }));
        }).catch(err => {

            debug("Catch ERROR:");
            debug(err);

            if (err.name === "user management") return showNotify({
                socketIo: socketIo,
                type: "danger",
                message: err.message
            });

            showNotify({
                socketIo: socketIo,
                type: "danger",
                message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору"
            });

            writeLogFile("error", err.toString());
        });
}

/**
 *      МОЖЕТ БЫТЬ ЭТО ИСПОЛЬЗОВАТЬ ПРИ УДАЛЕНИИ ПОЛЬЗОВАТЕЛЯ
 * 
 * then(() => {

                debug("Делаем запрос на получение списка пользователей");

                return new Promise((resolve, reject) => {
                    informationForPageManagementUsers((err, listUsers) => {
                        if (err) reject(err);
                        else resolve(listUsers);
                    });
                });
            }).then(listUsers => {

                debug("Отправляем полученный список в UI");
                debug(listUsers);

                socketIo.emit("update user list", JSON.stringify(listUsers));

            })
 * 
 */