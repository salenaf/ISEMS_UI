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
        "get list files to task": getListFilesTask,
        "get next chunk list tasks files not downloaded": getNextChunk,
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

            debug(authData);

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
                debug("----------");

                return;
            }

            //            debug(globalObject.getData("tmpModuleNetworkInteraction", sessionId));

            let tasksDownloadFiles = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles");

            debug(tasksDownloadFiles);

            /**
             * по идее здесь я должен получить список задач, по которым не
             * выгружались файлы. (это из globalObject.getData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles") )
             * после того взять следующую часть списка задач (расчитать основываясь на
             * общем количестве задач, размера части и порядкового номера задачи)
             * и отправить новый список с новым порядковым номером части в UI
             * 
             * 
             * доделать пагинатор и приступить к модальному окну, которое
             * должно появлятся при нажатии на облачко (загрузка файлов)
             * и в котором будет ПОДГРУЖАЕМЫЙ список файлов
             */
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
 * Обработчик запроса на получения списка файлов по выбранной задачи
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
function getListFilesTask(socketIo, data){
    debug("func 'getListFilesTask', START...");
    debug(data);
}