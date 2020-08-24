"use strict";

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const writeLogFile = require("../../libs/writeLogFile");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
const sendCommandsModuleNetworkInteraction = require("../../libs/processing/routeSocketIo/sendCommandsModuleNetworkInteraction");

/**
 * Модуль обработчик запросов выполняемых с целью получить
 * информацию о выполняемых задачах
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {   
    const handlers = {
        "network interaction: show info about all task": showTaskAllInfo,
        "network interaction: get list tasks to download files": showListTasksDownloadFiles,
        "network interaction: get list of unresolved tasks": showListUnresolvedTasks,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

/**
 * Обработчик запросов всей информации о задаче по ее ID.
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function showTaskAllInfo(socketIo, data){
    let funcName = " (func 'showTaskAllInfo')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            console.log("func 'showTaskAllInfo', send network interaction");

            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementRequestShowTaskAllInfo(data.arguments.taskID);
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
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

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        }); 
}

/**
 * Обработчик запросов списка задач по которым не были выгружены все файлы.
 * 
 * @param {*} socketIo 
 */
function showListTasksDownloadFiles(socketIo){
    let funcName = " (func 'showListTasksDownloadFiles')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementRequestGetListTasksDownloadFiles(socketIo);
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else {
                let msg = "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.";

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        }); 
}

/**
 * Обработчик запросов на получение списка необработанных задач (задач,
 * файлы по которым были выгружены, однако задача не была отмечена как
 * "рассмотренная")
 * 
 * @param {*} socketIo 
 */
function showListUnresolvedTasks(socketIo){
    let funcName = " (func 'showListUnresolvedTasks')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementRequestGetListUnresolvedTasks(socketIo);
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else {
                let msg = "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.";

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        }); 
}