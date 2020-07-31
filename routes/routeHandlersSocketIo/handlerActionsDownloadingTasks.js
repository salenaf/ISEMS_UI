"use strict";

const debug = require("debug")("hadt");

const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const getSessionId = require("../../libs/helpers/getSessionId.js");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");


/**
 * Модуль обработчик действий связанных со скачиванием файлов
 * в том числе обработка запроса часте списка задач, файлы по
 * которым не выгружались 
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {   
    const handlers = {
        "network interaction: stop downloading files": stopDownloadingFiles,
        "network interaction: start downloading files": startDownloadingFiles,
        "network interaction: get a list of files for a task": getListFilesTask,
        "network interaction: get next chunk list tasks files not downloaded": getNextChunk,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

/**
 * Обработчик запроса следующей части списка задач, файлы по
 * которым не выгружались
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function getNextChunk(socketIo, data){
    debug("func 'getNextChunk', START...");
    debug(data);

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
            debug(`user session ID: ${sessionId}`);

            if(!globalObject.hasData("tmpModuleNetworkInteraction", sessionId)){
                throw new MyError("management auth", "Ошибка авторизации. Информация о сессии недоступна.");
            }

            //            debug(globalObject.getData("tmpModuleNetworkInteraction", sessionId));

            let tasksDownloadFiles = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles");

            //debug(globalObject.getData("tmpModuleNetworkInteraction", sessionId));
            //debug(tasksDownloadFiles);

            if(data.nextChunk === 1){
                if(tasksDownloadFiles.numFound <= data.chunkSize){                   
                    return { list: tasksDownloadFiles.listTasksDownloadFiles, taskFound: tasksDownloadFiles.numFound };
                } else {
                    return { list: tasksDownloadFiles.listTasksDownloadFiles.slice(0, data.chunkSize), taskFound: tasksDownloadFiles.numFound };
                }
            } else {
                let numBegin = data.chunkSize * (data.nextChunk - 1);
                let nextNumBegin = numBegin + data.chunkSize;

                if(tasksDownloadFiles.numFound <= nextNumBegin){                    
                    return { list: tasksDownloadFiles.listTasksDownloadFiles.slice(numBegin), taskFound: tasksDownloadFiles.numFound };
                } else {                    
                    return { list: tasksDownloadFiles.listTasksDownloadFiles.slice(numBegin, nextNumBegin), taskFound: tasksDownloadFiles.numFound };
                } 
            }
        }).then((objInfo) => {
            debug(`count new tasks: ${objInfo.list.length}`);
            //debug(objInfo.list);

            let numFullChunks = 1;
            if(objInfo.taskFound > data.chunkSize){
                numFullChunks = Math.ceil(objInfo.taskFound/data.chunkSize);
            }

            socketIo.emit("module NI API", { 
                "type": "get list tasks files not downloaded",
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

            writeLogFile("error", err.toString()+funcName);
        }); 
}

/**
 * Обработчик запроса на получения списка файлов по выбранной задачи
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function getListFilesTask(socketIo, data){
    debug("func 'getListFilesTask', START...");
    debug(data);

    let funcName = " (func 'getListFilesTask')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }
    
            return;
        }).then(() => {
            return new Promise((resolve, reject) => {
                process.nextTick(() => {          
                    if(!globalObject.hasData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                        return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
                    }

                    let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            
                    if(conn !== null){ 
                        
                        debug("send request file list--->");

                        conn.sendMessage({                            
                            msgType: "command",
                            msgSection: "information search control",
                            msgInstruction: "get part of the list files",
                            taskID: require("../../libs/helpers/helpersFunc").getRandomHex(),
                            options: {
                                rtid: data.arguments.taskID,
                                ps: data.arguments.partSize,
                                olp: data.arguments.offsetListParts,
                            },
                        });
                    }    
            
                    resolve();
                });
            });
        }).catch((err) => {
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

            writeLogFile("error", err.toString()+funcName);
        });
}

/**
 * Обработчик запроса на скачивание файлов
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function startDownloadingFiles(socketIo, data){
    debug("func 'startDownloadingFiles', START...");
    debug(data);

    let funcName = " (func 'getListFilesTask')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }
    
            //может ли пользователь создавать задачи на фильтрацию
            if(!authData.document.groupSettings.management_network_interaction.element_settings.management_tasks_import.element_settings.resume.status){
                throw new MyError("management auth", "Невозможно отправить запрос на скачивание файлов. Недостаточно прав на выполнение данного действия.");
            }

            return;
        }).then(() => {
            return new Promise((resolve, reject) => {
                process.nextTick(() => {          
                    if(!globalObject.hasData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                        return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
                    }

                    let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            
                    if(conn !== null){ 
                        
                        debug("send request file list--->");

                        conn.sendMessage({                            
                            msgType: "command",
                            msgSection: "download control",
                            msgInstruction: "to start downloading",
                            taskID: require("../../libs/helpers/helpersFunc").getRandomHex(),
                            options: data.arguments.o,
                        });
                    }    
            
                    resolve();
                });
            });
        }).catch((err) => {
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

            writeLogFile("error", err.toString()+funcName);
        });
}

/**
 * Обработчик запроса на останов задачи по скачиванию файлов
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function stopDownloadingFiles(socketIo, data){
    debug("func 'stopDownloadingFiles', STOP...");

}
