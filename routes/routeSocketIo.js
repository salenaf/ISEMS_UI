"use strict";

const debug = require("debug")("routeSocketIo");

const ss = require("socket.io-stream");
const fs = require("fs");
const path = require("path");
//const validate = require("validate.js");

const globalObject = require("../configure/globalObject");
const showNotify = require("../libs/showNotify");
const writeLogFile = require("../libs/writeLogFile");
const getSessionId = require("../libs/helpers/getSessionId");
const checkUserAuthentication = require("../libs/check/checkUserAuthentication");
//const checkLimitNumberRequestsSocketIo = require('../libs/check/checkLimitNumberRequestsSocketIo');

/**
 * Маршруты для обработки информации передаваемой через протокол socket.io
 * Генератор событий (обрабатывает события от внешних источников, например API)
 *
 * @param {*} socketIo 
 * @param {*} object
 */ 
module.exports.modulesEventGenerator = function(socketIo) {
    let connModuleNetInteraction = globalObject.getData("descriptionAPI", "networkInteraction", "connection");

    //обработчик для модуля NetworkInteraction
    connModuleNetInteraction
        .on("connect", (msg) => {
            debug("--- CONNECTION ---");
            debug(msg);

            socketIo.emit("module NI API", { 
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": true
                },
            });

            setTimeout(() => {
                console.log("send command \"get an updated list of sources\"");
    
                connModuleNetInteraction.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "get an updated list of sources",
                    taskID: "nv8ej8hd8h8h38c8g49g49",
                    options: {}
                });
            }, 3000);
        }).on("message", (msg) => {
            debug("--- MESSAGE ---");
            debug(msg);
        }).on("close", (msg) => {
            debug("--- CONNECTION CLOSE ---");
            debug(msg);

            socketIo.emit("module NI API", { 
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": false
                },
            });
        })
        .on("information source control", (msg) => {
            debug("----- information source control -----");
            debug(msg);
            debug("--------------------------------------");

        }).on("command source control", (msg) => {
            debug("----- command source control ------");
            debug(msg);
            debug("------------------------------------------");

        }).on("information filtration control", (msg) => {
            debug("----- information filtration control -----");
            debug(msg);
            debug("------------------------------------------");

            /*writeFile.writeResivedMessage(JSON.stringify(msg), fileTestLog, (err) => {
            if (err) debug(err);
        });*/

        }).on("command filtration control", (msg) => {
            debug("----- command filtration control -----");
            debug(msg);
            debug("---------------------------------------");

        }).on("information download control", (msg) => {
            debug("----- information download control -----");
            debug(msg);
            debug("----------------------------------------");

            /*writeFile.writeResivedMessage(JSON.stringify(msg), fileTestLog, (err) => {
            if (err) debug(err);
        });*/

        }).on("command download control", (msg) => {
            debug("----- command download control -----");
            debug(msg);
            debug("----------------------------------------");

            /*writeFile.writeResivedMessage(JSON.stringify(msg), fileTestLog, (err) => {
            if (err) debug(err);
        });*/

        }).on("information search control", msg => {
            debug("====== information search control =====");
            debug(JSON.stringify(msg));
            /*        msg.options.slft.forEach((item) => {
            debug(item);
        });*/
            debug("=======================================");
        }).on("command information search control", msg => {
            debug("====== command information search control =====");
            debug(JSON.stringify(msg));
            /*        msg.options.slft.forEach((item) => {
            debug(item);
        });*/
            debug("=======================================");
        }).on("error", err => {
            debug("ERROR MESSAGE");
            debug(err);
        }).on("user notification", (notify) => {
            debug("---- RECEIVED user notification ----");
            debug(notify);

        }).on("error", () => {
            socketIo.emit("module NI API", { 
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": false
                },
            });
        });
};

/**
 * Маршруты для обработки информации передаваемой через протокол socket.io
 * Генератор событий
 *
 * @param {*} socketIo 
 * @param {*} object
 */
exports.eventEmitter = function(socketIo, object) {
    let handling = {
        //        "changingStatusSource": checkStatusSource.bind(null, socketIo)
    };

    console.log("--- script:routeSocketIo, Event Emitter ---");

    handling[object.type]();
};

/** 
 * Маршруты для обработки информации передаваемой через протокол socket.io
 * Обработчик событий поступающих от User Interface
 * 
 * @param {*} socketIo 
 **/
module.exports.eventHandlingUserInterface = function(socketIo) {
    /* --- УПРАВЛЕНИЕ ПАРОЛЯМИ ПО УМОЛЧАНИЮ --- */
    require("./routeHandlersSocketIo/handlerChangePassword")(socketIo);

    /* --- УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ --- */
    require("./routeHandlersSocketIo/handlerActionsUsers").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ГРУППАМИ --- */
    require("./routeHandlersSocketIo/handlerActionsGroups").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ОРГАНИЗАЦИЯМИ, ПОДРАЗДЕЛЕНИЯМИ И ИСТОЧНИКАМИ --- */
    require("./routeHandlersSocketIo/handlerActionsOrganizationsAndSources").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ЗАГРУЗКОЙ ФАЙЛОВ ПОЛУЧАЕМЫХ С User Interface --- */
    require("./routeHandlersSocketIo/handlerActionUploadFiles").addHandlers(ss, socketIo);
};
