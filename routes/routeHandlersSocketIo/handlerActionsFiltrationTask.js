"use strict";

/*
const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const commons = require("../../libs/helpers/commons");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
const sendCommandsModuleNetworkInteraction = require("../../libs/processing/routeSocketIo/sendCommandsModuleNetworkInteraction");
const informationForPageManagementOrganizationAndSource = require("../../libs/management_settings/informationForPageManagementOrganizationAndSource");
*/

const debug = require("debug")("handlerActionsFiltrationTask");

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

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
    debug("func 'startNewTask', START...");
    debug(data);

    let funcName = " (func 'startNewTask')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            debug("Авторизован ли пользователь");

            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            let filtrTaskParametr = authData.document.groupSettings.management_network_interaction.element_settings.management_tasks_filter.element_settings;

            debug(filtrTaskParametr);

            //может ли пользователь создавать задачи на фильтрацию
            if(!filtrTaskParametr.create.status){
                throw new MyError("management auth", "Невозможно отправить запрос на фильтрацию. Недостаточно прав на выполнение данного действия.");
            }

            return;
        }).then(() => {

            debug("проверяем параметры полученные от пользователя");

            let obj = (require("../../libs/processing/routeSocketIo/validationFileFilteringParameters"))(data.arguments);
            
            debug(obj);

            if(!obj.isValid){
                throw new MyError("management validation", obj.errorMsg);
            }

            return obj.filteringParameters;
        }).then((filteringParameters) => {
            debug("отправляем новые источники, если они есть, модулю сетевого взаимодействия");

            /**
 * Проверку на корректность входных параметров сделал,
 * по тестам все выполняется успешно. Следующим нужно
 * написать функцию которая отправляет информацию модулю и
 * заодно проверяет наличие подключения к модулю.
 * 
 * Кроме того нужно добавить информацию о задаче в globalObject,
 * туда добавляем ID задачи полученный из UI и по нему потом ищем задачу
 * и добавляем ID NIH_master. Это нужно что бы потом можно было остановить
 * выполнение задачи. 
 * 
 */

            //отправляем новые источники, если они есть, модулю сетевого взаимодействия
            //return sendCommandsModuleNetworkInteraction.sourceManagementsAdd(sourceList);
            return;
        }).then(() => {
            debug("запрос на фильтрацию сетевого трафика успешно отправлен");

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