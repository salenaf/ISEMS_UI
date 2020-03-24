/**
 * Модуль обработчик действий над организациями, подразделениями и источниками
 * 
 * Версия 0.1, дата релиза 24.03.2020
 */

"use strict";

const debug = require("debug")("handlerOAS");

const async = require("async");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const commons = require("../../libs/helpers/commons");
const showNotify = require("../../libs/showNotify");

const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

module.exports.addHandlers = function(socketIo) {
    debug("func 'addHandlers', START...");
    
    const handlers = {
        "add new entitys": addNewEntitys,
        "entity information": getEntityInformation,
        "change source info": changeSourceInfo,
        "delete source info": deleteSourceInfo,
        "change division info": changeDivisionInfo,
        "delete division info": deleteDivisionInfo,
        "change organization info": changeOrganizationInfo,
        "delete organization info": deleteOrganizationInfo,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

//обработчик для добавления новых сущностей
function addNewEntitys(socketIo, data){
    debug("func 'addNewEntitys', START...");
    debug(data);

    /**
            checkUserAuthentication(socketIo)
            .then(authData => {
            //авторизован ли пользователь
                if (!authData.isAuthentication) {
                    throw new MyError("organization and source management", "Пользователь не авторизован.");
                }

                //может ли пользователь создавать нового пользователя
            if (!authData.document.groupSettings.management_users.element_settings.create.status) {
                throw new MyError("organization and source management", "Невозможно добавить нового пользователя. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            //проверяем параметры полученные от пользователя
            if (!helpersFunc.checkUserSettingsManagementUsers(data.arguments)) {
                throw new MyError("user management", "Невозможно добавить нового пользователя. Один или более заданных параметров некорректен.");
            }
            }).then(() => {

            }).catch(err => {
                if (err.name === "organization and source management") {
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
     */
}

//получить информацию о сущности
function getEntityInformation(socketIo, data){
    debug("func 'getEntityInformation', START...");
    debug(data);

    switch(data.actionType){
    case "get info only source":
        debug("INFORMATION ONLY SOURCE");

        checkUserAuthentication(socketIo)
            .then(authData => {
                //авторизован ли пользователь
                if (!authData.isAuthentication) {
                    throw new MyError("organization and source management", "Пользователь не авторизован.");
                }
            }).then(() => {
                //проверяем параметры полученные от пользователя
                if (!(commons.getRegularExpression("stringAlphaNumEng")).test(data.arguments.sourceID)) {
                    throw new MyError("user management", "Невозможно получить информацию по источнику. Один или более заданных параметров некорректен.");
                }
            }).then(() => {
                //запрос информации к БД
                debug(`sending information to DB about id: ${data.arguments.entityId}`);

                return new Promise((resolve, reject) => {
                    mongodbQueryProcessor.querySelect(
                        models.modelSourcesParameter, { 
                            query: { id: data.arguments.entityId },
                            select: { _id: 0,  __v: 0, information_about_app: 0, id_division: 0 },
                        }, (err, list) => {
                            if(err) reject(err);
                            else resolve(list);
                        });
                });
            }).then((objInfo) => {
                debug(objInfo);

                socketIo.emit("entity: set info only source", {
                    arguments: objInfo,
                });
            }).catch(err => {
                if (err.name === "organization and source management") {
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

        break;

    case "get info about source":

        debug("INFORMATION ABOUT SOURCE");

        checkUserAuthentication(socketIo)
            .then(authData => {
            //авторизован ли пользователь
                if (!authData.isAuthentication) {
                    throw new MyError("organization and source management", "Пользователь не авторизован.");
                }
            }).then(() => {
            //проверяем параметры полученные от пользователя
                if (!(commons.getRegularExpression("stringAlphaNumEng")).test(data.arguments.sourceID)) {
                    throw new MyError("user management", "Невозможно получить информацию по источнику. Один или более заданных параметров некорректен.");
                }
            }).then(() => {
                //запрос информации к БД
                debug(`sending information to DB about id: ${data.arguments.entityId}`);

                return new Promise((resolve, reject) => {
                    mongodbQueryProcessor.querySelect(
                        models.modelSourcesParameter, { 
                            query: { id: data.arguments.entityId },
                            select: { _id: 0,  __v: 0 },
                        }, (err, list) => {
                            if(err) reject(err);
                            else resolve(list);
                        });
                }).then((sourceInfo) => {
                    return new Promise((resolve, reject) => {
                        mongodbQueryProcessor.querySelect(
                            models.modelDivisionBranchName, { 
                                query: { id: sourceInfo.id_division },
                                select: { _id: 0,  __v: 0 },
                            }, (err, list) => {
                                if(err) reject(err);
                                else resolve({ source: sourceInfo, division: list });
                            });
                    });
                }).then((objInfo) => {
                    return new Promise((resolve, reject) => {
                        mongodbQueryProcessor.querySelect(
                            models.modelOrganizationName, { 
                                query: { id: objInfo.division.id_organization },
                                select: { _id: 0,  __v: 0 },
                            }, (err, list) => {
                                if(err) reject(err);
                        
                                objInfo.organization = list;
                                resolve(objInfo);
                            });
                    });
                });        
            }).then((objInfo) => {
                debug(objInfo);

                socketIo.emit("entity: set info about source", {
                    arguments: objInfo,
                });
            }).catch(err => {
                if (err.name === "organization and source management") {
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

        break;

    case "get info about organization or division":

        debug("INFORMATION ABOUT ORGANIZATION OR DIVISION");

        break;
    }
}

//изменить информацию об источнике
function changeSourceInfo(socketIo, data){
    debug("func 'changeSourceInfo', START...");
    debug(data);

    /**
     * теперь получаю информацию по источнику,
     * необходимо проверить права пользователя на изменение информации
     * проверить полученные, от пользователя, данные
     * записать измененную информацию в БД
     * не забыть изменить время date_change 
     * 
     * отправить новую информацию об источниках для
     * перерисовке таблицы с источниками!!!
     */
}

//удалить всю информацию по источнику
function deleteSourceInfo(socketIo, data){
    debug("func 'deleteSourceInfo', START...");
    debug(data);
}

//изменить информацию о подразделении
function changeDivisionInfo(socketIo, data){
    debug("func 'changeDivisionInfo', START...");
    debug(data);
}

//удалить всю информацию о подразделении
function deleteDivisionInfo(socketIo, data){
    debug("func 'deleteDivisionInfo', START...");
    debug(data);
}

//изменить информацию об организации
function changeOrganizationInfo(socketIo, data){
    debug("func 'changeOrganizationInfo', START...");
    debug(data);
}

//удалить всю информацию об организации
function deleteOrganizationInfo(socketIo, data){
    debug("func 'deleteOrganizationInfo', START...");
    debug(data);
}