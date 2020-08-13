"use strict";

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

const MAX_CHUNK_NUM = 15;

/**
 * Модуль обработчик запросов с целью получения информации из
 * журнала информационных сообщений
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {   
    const handlers = {
        "network interaction: get notification log for source ID": showInformationForSourceID,
        "network interaction: get notification log next chunk": showInformationNextChunk,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function showInformationForSourceID(socketIo, data){
    let funcName = " (func 'showInformationForSourceID')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelNotificationLogISEMSNIH, {
                    isMany: true,
                    select: {
                        _id: 0, 
                        __v: 0, 
                    },
                    query: {
                        source_id: { $all: [ data.arguments.sourceID ] }
                    },
                    options: {
                        sort: { date_register: "desc", test: -1 },
                    },
                }, (err, result) => {
                    if(err) reject(err);
                    else resolve(result);
                });
            });
        }).then((result) => {
            let foundList;

            if(result.length <= MAX_CHUNK_NUM){
                foundList = result;
            } else {
                if(data.arguments.numberChunk === 1){
                    foundList = result.slice(0, MAX_CHUNK_NUM);
                } else {
                    let begin = (MAX_CHUNK_NUM * (data.arguments.numberChunk - 1));
                    foundList = result.slice(begin, begin + MAX_CHUNK_NUM);
                }
            }

            socketIo.emit("module NI API:send notification log for source ID", {
                options: {
                    addToList: (data.arguments.numberChunk !== 1), //добавлять в список сообщений или перезаписать его
                    foundList: foundList,
                    countDocument: result.length,
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

function showInformationNextChunk(socketIo, data){
    let funcName = " (func 'showInformationNextChunk')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelectWithLimit(models.modelNotificationLogISEMSNIH, {
                    select: { 
                        _id: 0, 
                        __v: 0, 
                    },
                    options: {
                        sort: { date_register: "desc", test: -1 },
                        skip: (MAX_CHUNK_NUM * (data.arguments.numberChunk - 1)),
                        limit: MAX_CHUNK_NUM,
                    },
                }, (err, documents) => {
                    if(err) reject(err);
                    else resolve(documents);
                });
            });
        }).then((foundList) => {
            socketIo.emit("module NI API:send notification log next chunk", {
                options: { foundList: foundList }
            });
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