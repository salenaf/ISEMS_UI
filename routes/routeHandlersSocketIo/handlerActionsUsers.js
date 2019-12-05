/**
 * Модуль обработчик дейсвий над пользователями
 * 
 * Версия 0.1, дата релиза 04.12.2019
 */

"use strict";

const async = require("async");
const debug = require("debug")("handlerActionsUsers");

const models = require("../../controllers/models");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const createUniqID = require("../../libs/helpers/createUniqID");
const informationAboutUser = require("../../libs/management_settings/informationAboutUser");
const informationItemGroups = require("../../libs/management_settings/informationItemGroups");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

class MyError extends Error {
    constructor(name, msg) {
        super(msg);
        this.message = msg;
        this.name = name;
    }
}

module.exports.handlerActions = function(socketIo) {
    const handlers = {
        "add new user": addUser,
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
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new Error("Пользователь не авторизован.");
            }

            //может ли пользователь создавать нового пользователя
            if (!authData.document.groupSettings.management_users.element_settings.create.status) {
                throw new Error("Невозможно добавить нового пользователя. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            debug("Проверка прав пользователей выполненна успешно");

            //проверяем параметры полученные от пользователя
            if (!helpersFunc.checkUserSettingsManagementUsers(data.arguments)) {
                throw new Error("Невозможно добавить нового пользователя. Один или более заданных параметров некорректен.");
            }
        }).then(() => {
            debug("Проверка параметров заданных пользователем выполненна успешно");
            async.parallel({
                listGroup: (callbackParallel) => {
                    //проверяем наличие группы 
                    informationItemGroups((err, listGroup) => {
                        if (err) return callbackParallel(err);

                        let errorMsg = `Невозможно добавить нового пользователя. Группы ${data.arguments.work_group} не существует.`;
                        let myError = new MyError("group", errorMsg);

                        if (!listGroup.some(elem => elem === data.arguments.work_group)) {
                            callbackParallel(myError);
                        }

                        callbackParallel(null, true);
                    });
                },
                userInfo: (callbackParallel) => {
                    //проверяем есть ли уже пользователь с таким логином 
                    informationAboutUser(data.arguments.user_login, (err, userInfo) => {
                        if (err) return callbackParallel(err);

                        let errorMsg = `Невозможно добавить нового пользователя. Пользователь с логином ${data.arguments.user_login}`;
                        let myError = new MyError("login", errorMsg);
                        if (userInfo !== null) return callbackParallel(myError);
                        else callbackParallel(null, true);
                    });
                }
            }, (err, result) => {
                if (err) {
                    if (err.name === "group") {

                    } else if (err.name === "login") {

                    } else {
                        throw err;
                    }
                }
            });
            /**
             * ДОДЕЛАТЬ ДОБАВЛЕНИЕ ПОЛЬЗОВАТЕЛЕЙ
             * можно делать тесты по взаимодействию с БД через jasmine
             */


        }).then(() => {

        }).then(() => {
            debug("Проверка наличия указанной группы и отсутствия такого же логина пользователя выполнена успешно");

            new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryCreate(models.modelUser, {
                    document: {
                        user_id: createUniqID.getMD5("user_name_administrator"),
                        date_register: +(new Date()),
                        date_change: +(new Date()),
                        login: data.arguments.user_login,
                        password: data.arguments.user_password,
                        group: data.arguments.work_group,
                        user_name: data.arguments.user_name,
                        settings: {
                            sourceMainPage: []
                        }
                    }
                }, err => {
                    if (err) reject(err);
                    else resolve();
                });
            }).then(() => {
                debug("Делаем запрос на получение списка пользователей");

                /** 
                 * ДОДЕЛАТЬ.
                 * делать запрос на получения нового списка и отправлять в UI
                 */

            }).catch(err => {
                debug(err);
            });
        });
}