/**
 * Модуль обработчик дейсвий над пользователями
 * 
 * Версия 0.1, дата релиза 04.12.2019
 */

"use strict";

const debug = require("debug")("handlerActionsUsers");

const models = require("../../controllers/models");
const createUniqID = require("../../libs/helpers/createUniqID");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

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
                throw new Error("Невозможно добавить нового пользователя, недостаточно прав на выполнение данного действия.");
            }

            /*
            
                ВЫПОЛНИТЬ ПРОВЕРКУ ДАННЫХ ПРИНЯТЫХ ОТ ПОЛЬЗОВАТЕЛЯ
            
            */


        }).then(() => {
            debug("Проверка прав пользователей выполненна успешно");

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
            }).catch(err => {
                debug(err);
            });
        });
}