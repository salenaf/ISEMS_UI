"use strict";

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
//const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
//const informationForPageManagementOrganizationAndSource = require("../../libs/management_settings/informationForPageManagementOrganizationAndSource");

/**
 * Модуль обработчик действий над правилами СОА
 * Поиск в бд указанный SID 
 * 
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {   
    const handlers = {
        "sid_bd: find-sid": findRuleToSID,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function findRuleToSID(socketIo, data){
    console.log("func 'findRuleToSID'");
    console.log(data);

    let funcName = " (func 'findRuleToSID')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }
        }).then(() => {
        //запрос к БД
            new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(
                    models.modelSOARules, { 
                        query: { sid: data.sid }
                    },
                    (err, list) => {
                        if(err){
                            reject(new MyError("management request DB", err.toString()+funcName));
                        }

                        console.log(list);

                        //проверить на пустоту
                        //если пустой 
                        showNotify({
                            socketIo: socketIo,
                            type: "warning",
                            message: "Правило не найдено."
                        });

                        //если нет
                        socketIo.emit("result find SID", list);

                        resolve();
                        //console.log(list);
                        //if(err) callbackParallel(err);
                        //else callbackParallel(null, list);
                    });
            });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            } else if (err.name === "management validation") {               
                err.message.forEach((msg) => {
                    showNotify({
                        socketIo: socketIo,
                        type: "danger",
                        message: msg
                    });
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        });

    /*checkUserAuthentication(socketIo)
        .then((authData) => {
        //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }
        }).then(() => {
            //проверка входных параметров


        }).then(() => {
            //запрос к БД
            mongodbQueryProcessor.querySelect(
                models.modelSOARules, { 
                    query: {sid: data.sid }
                },
                (err, list) => {
                    if(err){
                        throw new MyError("management request DB", err.toString()+funcName);
                    }

                    return list;
                    //console.log(list);
                    //if(err) callbackParallel(err);
                    //else callbackParallel(null, list);
                });
        }).then((list) => {
            //проверить на пустоту
            //если пустой 
            showNotify({
                socketIo: socketIo,
                type: "warning",
                message: "Правило не найдено."
            });

            //если нет
            socketIo.emit("result find SID", list);
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            } else if (err.name === "management validation") {               
                err.message.forEach((msg) => {
                    showNotify({
                        socketIo: socketIo,
                        type: "danger",
                        message: msg
                    });
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        });*/

    /* checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

//            return authData.document.groupSettings.management_organizations_and_sources.element_settings;
        }).then((authData) => {
            //проверяем параметры полученные от пользователя
            let obj = (require("../../libs/processing/routeSocketIo/validationObjectNewEntitys"))(data.arguments);
            obj.authData = authData;

            return obj;
        }).then(({ result: newObjectEntity, errMsg: listErrors, authData: ad }) => {
            //наличие ошибок при валидации данных полученных от пользователя
            if(listErrors.length > 0){
                throw new MyError("management validation", listErrors);
            }

            //проверяем права пользователя на добавление сущностей различных типов
            let { entityList, errMsg } = checkListEntitiesBasedUserPrivileges(newObjectEntity, ad);
            if(errMsg){
                throw errMsg;
            }

            return entityList;
        }).then((entityList) => {
            //добавляем новые сущности в БД
            return (require("../../libs/processing/routeSocketIo/insertNewEntity"))(entityList);
        }).then(() => {
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Новые сущности были успешно добавлены."
            });      
        }).finally(() => {
            //получаем новый краткий список с информацией по сущностям
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            }).then((shortSourceList) => {             
                socketIo.emit("entity: new short source list", {
                    arguments: shortSourceList,
                }); 
            });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            } else if (err.name === "management validation") {               
                err.message.forEach((msg) => {
                    showNotify({
                        socketIo: socketIo,
                        type: "danger",
                        message: msg
                    });
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        });    
}*/
}