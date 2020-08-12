"use strict";

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

const MAX_CHUNK_NUM = 10;

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
                }, (err, result) => {
                    if(err) reject(err);
                    else resolve(result);
                });
            });
        }).then((result) => {

            console.log("func 'networkInteractionHandlerNotificationLog', (showInformationForSourceID)");
            console.log(result);

            let foundList;

            if(result.length <= MAX_CHUNK_NUM){
                foundList = result;

                console.log("111111111");
            } else {

                console.log("222222222");

                if(data.arguments.numberChunk === 1){

                    console.log("33333333");

                    foundList = result.slice(0, MAX_CHUNK_NUM);
                } else {

                    console.log("44444444");

                    let begin = (MAX_CHUNK_NUM * (data.arguments.numberChunk - 1));
                    foundList = result.slice(begin, begin + MAX_CHUNK_NUM);
                }
            }

            console.log("--- foundList ---");
            console.log(foundList);

            /**
 *      !!!!!!!
 * 
 * Потестировать и отладить этот раздел
 * 
 * 
 *      !!!!!!!
 */

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

    /*require("../../../middleware/mongodbQueryProcessor")
                .querySelect(require("../../../controllers/models")
                    .modelNotificationLogISEMSNIH, {
                    isMany: true,
                    select: { 
                        _id: 0, 
                        __v: 0, 
                    },
                    options: {
                        sort: { date_register: "desc", test: -1 },
                        limit: 100,
                    },
                }, (err, documents) => {
                    if(err) callback(err);
                    else callback(null, documents);
                });


            /**
                 * для вывода заданного интервала
                 * 
                 * Query.prototype.skip()
Parameters
val «Number»
Specifies the number of documents to skip.

Example
query.skip(100).limit(20)
пропустить 100 и вывести 20
                 */

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {

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