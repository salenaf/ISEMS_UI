/**
 * Модуль обработчик действий над пользователями
 * 
 * Версия 0.2, дата релиза 10.12.2019
 */

"use strict";

const async = require("async");
const crypto = require("crypto");

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
    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("user management", "Пользователь не авторизован.");
            }

            //может ли пользователь создавать нового пользователя
            if (!authData.document.groupSettings.management_users.element_settings.create.status) {
                throw new MyError("user management", "Невозможно добавить нового пользователя. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            //проверяем параметры полученные от пользователя
            if (!helpersFunc.checkUserSettingsManagementUsers(data.arguments)) {
                throw new MyError("user management", "Невозможно добавить нового пользователя. Один или более заданных параметров некорректен.");
            }
        }).then(() => {
            return new Promise((resolve, reject) => {
                async.parallel({
                    listGroup: (callbackParallel) => {
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
                        //проверяем есть ли уже пользователь с таким логином 
                        informationAboutUser.getInformationByLogin(data.arguments.user_login, (err, userInfo) => {
                            if (err) return callbackParallel(err);

                            let errorMsg = `Невозможно добавить нового пользователя. Пользователь с логином '${data.arguments.user_login}' уже существует.`;
                            let myError = new MyError("user management", errorMsg);

                            if (userInfo !== null) callbackParallel(myError);
                            else callbackParallel(null);
                        });
                    }
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }).then(() => {
            return new Promise((resolve, reject) => {
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
                }, (err) => {
                    if (err) reject(err);
                    else resolve(newUser);
                });
            });
        }).then((newUser) => {
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Пользователь успешно добавлен."
            });

            socketIo.emit("add new user", JSON.stringify(newUser));
        }).catch((err) => {
            if (err.name === "user management") {
                return showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            }

            showNotify({
                socketIo: socketIo,
                type: "danger",
                message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
            });

            writeLogFile("error", err.toString());
        });
}

function updateUser(socketIo, data) {
    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("user management", "Пользователь не авторизован.");
            }

            //может ли пользователь изменять информацию о пользователе
            if (!authData.document.groupSettings.management_users.element_settings.edit.status) {
                throw new MyError("user management", "Невозможно изменить информацию о пользователе. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            //проверяем параметры полученные от пользователя
            if (!helpersFunc.checkUserSettingsManagementUsers(data.arguments)) {
                throw new MyError("user management", "Невозможно изменить информацию о пользователе. Один или более заданных параметров некорректен.");
            }
        }).then(() => {
            return new Promise((resolve, reject) => {
                async.parallel({
                    listGroup: (callbackParallel) => {
                        //проверяем наличие группы 
                        informationItemGroups((err, listGroup) => {
                            if (err) return callbackParallel(err);

                            let errorMsg = `Невозможно изменить информацию о пользователе. Группы '${data.arguments.work_group}' не существует.`;
                            let myError = new MyError("user management", errorMsg);

                            if (!listGroup.some(elem => elem === data.arguments.work_group)) callbackParallel(myError);
                            else callbackParallel(null);
                        });
                    },
                    userInfo: (callbackParallel) => {
                        //проверяем есть ли уже пользователь с таким логином 
                        informationAboutUser.getInformationByLogin(data.arguments.user_login, (err, userInfo) => {
                            if (err) return callbackParallel(err);

                            let errorMsg = `Невозможно изменить информацию о пользователе. Пользователя с логином '${data.arguments.user_login}' не существует.`;
                            let myError = new MyError("user management", errorMsg);

                            if (userInfo === null) callbackParallel(myError);
                            else callbackParallel(null, userInfo);
                        });
                    }
                }, (err, result) => {
                    if (err) reject(err);
                    else resolve(result.userInfo);
                });
            });
        }).then((userInfo) => {
            return new Promise((resolve, reject) => {
                let md5string = crypto.createHash("md5")
                    .update(data.arguments.user_password)
                    .digest("hex");

                let updateUser = {
                    userID: userInfo.user_id,
                    dateRegister: userInfo.date_register,
                    dateChange: +(new Date()),
                    login: userInfo.login,
                    userName: data.arguments.user_name,
                    group: data.arguments.work_group,
                };

                let userInfoUpdate = {
                    date_change: updateUser.dateChange,
                    password: hashPassword.getHashPassword(md5string, "isems-ui"),
                    settings: {
                        sourceMainPage: [],
                    },
                };

                if (userInfo.login !== "administrator") {
                    userInfoUpdate.group = updateUser.group;
                    userInfoUpdate.user_name = updateUser.userName;
                }

                mongodbQueryProcessor.queryUpdate(models.modelUser, {
                    id: userInfo.id,
                    update: userInfoUpdate,
                }, (err) => {
                    if (err) reject(err);
                    else resolve(updateUser);
                });
            });
        }).then((updateUser) => {
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Информация о пользователе успешно изменена."
            });

            socketIo.emit("update user", JSON.stringify(updateUser));
        }).catch((err) => {
            if (err.name === "user management") {
                return showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            }

            showNotify({
                socketIo: socketIo,
                type: "danger",
                message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору"
            });

            writeLogFile("error", err.toString());
        });
}

function deleteUser(socketIo, data) {
    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("user management", "Пользователь не авторизован.");
            }

            //может ли пользователь удалять пользователя
            if (!authData.document.groupSettings.management_users.element_settings.delete.status) {
                throw new MyError("user management", "Невозможно удалить пользователя. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
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
        }).then((userInfo) => {
            if (userInfo === null || (typeof userInfo === "undefined")) {
                throw new MyError("user management", "Невозможно удалить пользователя, не найден пользователь с заданным идентификатором.");
            }

            if (userInfo.login === "administrator") {
                throw new MyError("user management", "Невозможно удалить пользователя, так как пользователь является администратором.");
            }

        }).then(() => {
            new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryDelete(require("../../controllers/models").modelUser, { query: { user_id: data.arguments.userID } }, err => {
                    if (err) reject(err);
                    resolve();
                });
            });
        }).then(() => {
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Пользователь успешно удален"
            });

            socketIo.emit("del selected user", JSON.stringify({ userID: data.arguments.userID }));
        }).catch((err) => {
            if (err.name === "user management") {
                return showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            }

            showNotify({
                socketIo: socketIo,
                type: "danger",
                message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору"
            });

            writeLogFile("error", err.toString());
        });
}