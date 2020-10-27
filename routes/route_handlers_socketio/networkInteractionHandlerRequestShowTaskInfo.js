"use strict";

const debug = require("debug")("nihrsti");

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const getSessionId = require("../../libs/helpers/getSessionId.js");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
const sendCommandsModuleNetworkInteraction = require("../../libs/processing/route_socketio/sendCommandsModuleNetworkInteraction");

/**
 * Модуль обработчик запросов выполняемых с целью получить
 * информацию о выполняемых задачах
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {
    const handlers = {
        "network interaction: get list all tasks": getListAllTasks,
        "network interaction: show info about all task": showTaskAllInfo,
        "network interaction: get list tasks to download files": showListTasksDownloadFiles,
        "network interaction: get list of unresolved tasks": showListUnresolvedTasks,
        "network interaction: start search task": searchInformationAboutTasks,
        "network interaction: get next chunk list all tasks": getNextChunkAllTasks,
        "network interaction: get next chunk list unresolved tasks": getNextChunkUnresolvedTasks,
        "network interaction: delete all information about a task": sendReguestDeleteInformationAboutTask,
        "network interaction: get analytics information about task id": getAnalyticsInformationAboutTaskID,
        "network interaction: mark an task as completed": markTaskCompleted,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

/**
 * Обработчик запросов для получения списка всех задач
 * 
 * @param {*} socketIo 
 */
function getListAllTasks(socketIo) {
    let funcName = " (func 'getListAllTasks')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementRequestGetListAllTasks(socketIo);
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

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запросов всей информации о задаче по ее ID.
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function showTaskAllInfo(socketIo, data) {
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

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запросов списка задач по которым не были выгружены все файлы.
 * 
 * @param {*} socketIo 
 */
function showListTasksDownloadFiles(socketIo) {
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

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запросов на получение списка необработанных задач (задач,
 * файлы по которым были выгружены, однако задача не была отмечена как
 * "рассмотренная")
 * 
 * @param {*} socketIo 
 */
function showListUnresolvedTasks(socketIo) {
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

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запроса для поиска информации по заданным параметрам
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function searchInformationAboutTasks(socketIo, data) {
    let funcName = " (func 'searchInformationAboutTasks')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementRequestSearchInformationAboutTasks(socketIo, data.arguments);
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

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запроса следующей части списка всех задач, найденных пользователем
 * через поисковую машину
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function getNextChunkAllTasks(socketIo, data) {
    let funcName = " (func 'getNextChunk')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            return new Promise((resolve, reject) => {
                getSessionId("socketIo", socketIo, (err, sessionId) => {
                    if (err) reject(err);
                    else resolve(sessionId);
                });
            });
        }).then((sessionId) => {
            console.log(`sessionId: ${sessionId}, ${funcName}`);

            if (!globalObject.hasData("tmpModuleNetworkInteraction", sessionId)) {
                throw new MyError("management auth", "Ошибка авторизации. Информация о сессии недоступна.");
            }

            let resultFoundTasks = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "resultFoundTasks");

            if (data.nextChunk === 1) {
                if (resultFoundTasks.numFound <= data.chunkSize) {
                    return { list: resultFoundTasks.listTasksDownloadFiles, taskFound: resultFoundTasks.numFound };
                } else {
                    return { list: resultFoundTasks.listTasksDownloadFiles.slice(0, data.chunkSize), taskFound: resultFoundTasks.numFound };
                }
            } else {
                let numBegin = data.chunkSize * (data.nextChunk - 1);
                let nextNumBegin = numBegin + data.chunkSize;

                if (resultFoundTasks.numFound <= nextNumBegin) {
                    return { list: resultFoundTasks.listTasksDownloadFiles.slice(numBegin), taskFound: resultFoundTasks.numFound };
                } else {
                    return { list: resultFoundTasks.listTasksDownloadFiles.slice(numBegin, nextNumBegin), taskFound: resultFoundTasks.numFound };
                }
            }
        }).then((objInfo) => {
            console.log(`BEFORE ${funcName}`);

            let numFullChunks = 1;
            if (objInfo.taskFound > data.chunkSize) {
                numFullChunks = Math.ceil(objInfo.taskFound / data.chunkSize);
            }

            console.log(`SEND a list of found tasks ${funcName}`);

            socketIo.emit("module NI API", {
                "type": "send a list of found tasks",
                "taskID": data.taskID,
                "options": {
                    p: {
                        cs: data.chunkSize, //размер части
                        cn: numFullChunks, //всего частей
                        ccn: data.nextChunk, //номер текущей части
                    },
                    tntf: objInfo.taskFound,
                    slft: require("../../libs/helpers/helpersFunc").modifyListFoundTasks(objInfo.list),
                }
            });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
                });
            }

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запроса следующей части списка задач не отмеченных
 * пользователем как завершенные
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function getNextChunkUnresolvedTasks(socketIo, data) {
    let funcName = " (func 'getNextChunk')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            return new Promise((resolve, reject) => {
                getSessionId("socketIo", socketIo, (err, sessionId) => {
                    if (err) reject(err);
                    else resolve(sessionId);
                });
            });
        }).then((sessionId) => {
            debug(`sessionId: ${sessionId}, ${funcName}`);

            if (!globalObject.hasData("tmpModuleNetworkInteraction", sessionId)) {
                throw new MyError("management auth", "Ошибка авторизации. Информация о сессии недоступна.");
            }

            let unresolvedTask = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "unresolvedTask");

            if (data.nextChunk === 1) {
                if (unresolvedTask.numFound <= data.chunkSize) {
                    return { list: unresolvedTask.listUnresolvedTask, taskFound: unresolvedTask.numFound };
                } else {
                    return { list: unresolvedTask.listUnresolvedTask.slice(0, data.chunkSize), taskFound: unresolvedTask.numFound };
                }
            } else {
                let numBegin = data.chunkSize * (data.nextChunk - 1);
                let nextNumBegin = numBegin + data.chunkSize;

                if (unresolvedTask.numFound <= nextNumBegin) {
                    return { list: unresolvedTask.listUnresolvedTask.slice(numBegin), taskFound: unresolvedTask.numFound };
                } else {
                    return { list: unresolvedTask.listUnresolvedTask.slice(numBegin, nextNumBegin), taskFound: unresolvedTask.numFound };
                }
            }
        }).then((objInfo) => {
            debug(`BEFORE ${funcName}`);

            let numFullChunks = 1;
            if (objInfo.taskFound > data.chunkSize) {
                numFullChunks = Math.ceil(objInfo.taskFound / data.chunkSize);
            }

            debug(`SEND a list of found tasks ${funcName}`);

            socketIo.emit("module NI API", {
                "type": "send a list of found unresolved tasks",
                "taskID": data.taskID,
                "options": {
                    p: {
                        cs: data.chunkSize, //размер части
                        cn: numFullChunks, //всего частей
                        ccn: data.nextChunk, //номер текущей части
                    },
                    tntf: objInfo.taskFound,
                    slft: require("../../libs/helpers/helpersFunc").modifyListFoundTasks(objInfo.list),
                }
            });
        }).catch((err) => {

            debug("--- networkInteractionHandlerRequestShowTaskInfo ---");
            debug(err);

            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
                });
            }

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запроса на удаление информации по выбранным задачам
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function sendReguestDeleteInformationAboutTask(socketIo, data) {
    let funcName = " (func 'sendReguestDeleteInformationAboutTask')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            let groupSettings = authData.document.groupSettings.management_network_interaction.element_settings.management_uploaded_files.element_settings;
            //может ли пользователь удалять задачи
            if (!groupSettings.delete.status) {
                throw new MyError("management auth", "Невозможно отправить запрос на фильтрацию. Недостаточно прав на выполнение данного действия.");
            }

            return;
        }).then(() => {
            //отправляем задачу модулю сетевого взаимодействия
            return sendCommandsModuleNetworkInteraction.managementRequestDeleteInformationAboutTask(data.listTaskID);
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

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запроса на получение аналитической информации о задаче
 * и связанных с ней файлов по уникальному иднтификатору задачи
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function getAnalyticsInformationAboutTaskID(socketIo, data) {
    let funcName = " (func 'getAnalyticsInformationAboutTaskID')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            return sendCommandsModuleNetworkInteraction.managementRequestShowAnalyticsInformationAboutTaskID(data.arguments.taskID);
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

            writeLogFile("error", err.toString() + funcName);
        });
}

/**
 * Обработчик запроса для установки задачи как 'завершенная'
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function markTaskCompleted(socketIo, data) {
    debug("func 'markTaskCompleted'");
    debug(data);

    let funcName = " (func 'markTaskCompleted')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            let groupSettings = authData.document.groupSettings.management_network_interaction.element_settings.management_uploaded_files.element_settings;
            //может ли пользователь удалять задачи
            if (!groupSettings.status_change.status) {
                throw new MyError("management auth", "Невозможно отметить задачу как завершенную. Недостаточно прав на выполнение данного действия.");
            }

            debug(authData);

            return authData.document.userName;
        }).then((userName) => {
            debug("parametr validate");

            let description = data.arguments.description;

            if (!helpersFunc.checkInputValidation({ name: "hexSumMD5", value: data.arguments.taskID })) {
                throw new MyError("management validation", "Принят некорректный идентификатор задачи.");
            }

            if (!helpersFunc.checkInputValidation({ name: "inputDescription", value: data.arguments.description })) {
                description = "";
            }

            return {
                taskID: data.arguments.taskID,
                userName: userName,
                description: description,
            };
        }).then((validData) => {
            //отправляем задачу модулю сетевого взаимодействия

            debug(`SEND task ID '${data.arguments.taskID}' ---> module_NIH`);

            return sendCommandsModuleNetworkInteraction.managementRequestMarkTaskCompleted(validData);
        }).catch((err) => {
            if ((err.name === "management auth") || (err.name === "management validation")) {
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

            writeLogFile("error", err.toString() + funcName);
        });
}