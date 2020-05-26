"use strict";

const debug = require("debug")("handlerActionsFiltrationTask");

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
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

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }
            
            /**
             * authData.document: {
                userLogin: objData.userData.login,
                userName: objData.userData.user_name,
                userGroup: objData.userData.group,
                groupSettings: objData.groupData,
                userSettings: objData.userData.settings,
            }
             */

            let filtrTaskParametr = authData.document.groupSettings.management_network_interaction.element_settings.management_tasks_filter.element_settings;
            //может ли пользователь создавать задачи на фильтрацию
            if(!filtrTaskParametr.create.status){
                throw new MyError("management auth", "Невозможно отправить запрос на фильтрацию. Недостаточно прав на выполнение данного действия.");
            }

            return { login: authData.document.userLogin, name: authData.document.name };
        }).then((userInfo) => {
            let obj = (require("../../libs/processing/routeSocketIo/validationFileFilteringParameters"))(data.arguments);
            if(!obj.isValid){
                throw new MyError("management validation", obj.errorMsg);
            }

            return { userInfo: userInfo, filterParam: obj.filteringParameters };
        }).then((parameters) => {
            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementTaskFilteringStart(parameters.filterParam, parameters.login, parameters.name);
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
    debug("func 'stopTask', START...");
    debug(data);

}