/**
 * Модуль обработчик дейсвий над пользователями
 * 
 * Версия 0.2, дата релиза 10.12.2019
 */

"use strict";

const async = require("async");
const debug = require("debug")("handlerActionsUsers");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const commons = require("../../libs/helpers/commons");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
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
                        informationAboutUser(data.arguments.user_login, (err, userInfo) => {
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

            new Promise((resolve, reject) => {

                debug("добавляем нового пользователя");

                let newUser = {
                    userID: createUniqID.getMD5(`user_name_${data.arguments.user_login}`),
                    dateRegister: +(new Date()),
                    dateChange: +(new Date()),
                    login: data.arguments.user_login,
                    userName: data.arguments.user_name,
                    group: data.arguments.work_group,
                };

                mongodbQueryProcessor.queryCreate(models.modelUser, {
                    document: {
                        user_id: newUser.userID,
                        date_register: newUser.dateRegister,
                        date_change: newUser.dateChange,
                        login: newUser.login,
                        password: data.arguments.user_password,
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
            }).then(newUser => {

                debug("Отправляем полученный список в UI");
                debug(newUser);

                socketIo.emit("add new user", JSON.stringify(newUser));

            }).catch(err => {

                debug(err);

                if (err.name === "user management") return showNotify("danger", err.message);

                showNotify("danger", "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.");
                writeLogFile("error", err.toString());
            });
        });
}

function updateUser(socketIo, data) {

}

function deleteUser(socketIo, data) {
    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then(authData => {

            debug("авторизован ли пользователь");

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
            debug("Ищем пользователя с указанным ID и проверяем есть ли он и его логин не 'Administrator'");


            /**
             * Дописать проверку пользователя на наличие и что бы его логин не был 'Administrator'
             * Сделать удаление пользователя и отправку в UI подтверждение удаления
             *      В ТЕСТАХ ПОЧТИ ДОПИСАЛ ПРОВЕРКУ УДАЛЕНИЯ ПОЛЬЗОВАТЕЛЯ
             * 
             * Кроме того написать в UI ВЫВОД ИНФОРМАЦИОННых СООБЩЕНИй!!!!
             */

        }).catch(err => {

            debug(err);

            if (err.name === "user management") return showNotify("danger", err.message);

            showNotify("danger", "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.");
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