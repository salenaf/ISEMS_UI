"use strict";

const debug = require("debug")("handlerActionsFiltrationTask");

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const writeLogFile = require("../../libs/writeLogFile");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
const sendCommandsModuleNetworkInteraction = require("../../libs/processing/routeSocketIo/sendCommandsModuleNetworkInteraction");

/**
 * Модуль обработчик действий связанных с фильтрацией файлов
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {   
    const handlers = {
        "start new filtration task": startNewTask,
        "stop filtration task": stopTask,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function startNewTask(socketIo, data){
    let funcName = " (func 'startNewTask')";

    debug(data);

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            let filtrTaskParametr = authData.document.groupSettings.management_network_interaction.element_settings.management_tasks_filter.element_settings;
            //может ли пользователь создавать задачи на фильтрацию
            if(!filtrTaskParametr.create.status){
                throw new MyError("management auth", "Невозможно отправить запрос на фильтрацию. Недостаточно прав на выполнение данного действия.");
            }

            return { login: authData.document.userLogin, name: authData.document.userName };
        }).then((userInfo) => {
            debug("user info");
            debug(userInfo);

            let obj = (require("../../libs/processing/routeSocketIo/validationFileFilteringParameters"))(data.arguments);
            if(!obj.isValid){
                throw new MyError("management validation", obj.errorMsg);
            }

            return { userInfo: userInfo, filterParam: obj.filteringParameters };
        }).then((parameters) => {

            debug(parameters);

            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementTaskFilteringStart(parameters.filterParam, parameters.userInfo.login, parameters.userInfo.name);
        }).then(() => {          
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Запрос на выполнение задачи по фильтрации сетевого трафика успешно отправлен.",
            });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else if (err.name === "management validation") {               
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: `Задача по фильтрации отклонена. ${err.message}`,
                });
            } else if (err.name === "management network interaction") {
            //при отсутствии доступа к модулю сетевого взаимодействия
                showNotify({
                    socketIo: socketIo,
                    type: "warning",
                    message: err.message.toString()
                });            
            } else {
                let msg = "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.";

                if((err.message.toString()).includes("duplicate key")){
                    msg = "Совпадение ключевых полей, запись в базу данных невозможен.";
                }

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        }); 
}

function stopTask(socketIo, data){
    let funcName = " (func 'stopTask')";

    debug("func 'stopTask', START...");
    debug(data);
 
    checkUserAuthentication(socketIo)
        .then((authData) => {
        //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            let filtrTaskParametr = authData.document.groupSettings.management_network_interaction.element_settings.management_tasks_filter.element_settings;
            //может ли пользователь останавливать задачи на фильтрацию
            if(!filtrTaskParametr.stop.status){
                throw new MyError("management auth", "Невозможно отправить запрос на фильтрацию. Недостаточно прав на выполнение данного действия.");
            }

            return { login: authData.document.userLogin, name: authData.document.userName };
        }).then((userInfo) => {
            debug("user info");
            debug(userInfo);

            if(!helpersFunc.checkInputValidation({ 
                name: "hexSumMD5", 
                value: data.arguments.taskID,
            })){
                throw new MyError("management validation", "Принят некорректный идентификатор задачи.");
            }

            if(!helpersFunc.checkInputValidation({ 
                name: "hostID", 
                value: data.arguments.sourceID,
            })){
                throw new MyError("management validation", "Принят некорректный идентификатор источника.");
            }

            return;
        }).then(() => {

            debug(`sending request filtration stop task with ID: ${data.arguments.taskID}, source ID: ${data.arguments.sourceID}`);

            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementTaskFilteringStop(data.arguments.taskID, data.arguments.sourceID);
        }).then(() => {          
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Запрос на останов задачи по фильтрации сетевого трафика успешно отправлен.",
            });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else if (err.name === "management validation") {               
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: `Останов задачи по фильтрации отклонён. ${err.message}`,
                });
            } else if (err.name === "management network interaction") {
                //при отсутствии доступа к модулю сетевого взаимодействия
                showNotify({
                    socketIo: socketIo,
                    type: "warning",
                    message: err.message.toString()
                });            
            } else {
                let msg = "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.";

                if((err.message.toString()).includes("duplicate key")){
                    msg = "Совпадение ключевых полей, запись в базу данных невозможен.";
                }

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        }); 
}