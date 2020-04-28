"use strict";

const debug = require("debug")("routeSocketIo");

const ss = require("socket.io-stream");

const showNotify = require("../libs/showNotify");
const globalObject = require("../configure/globalObject");
const writeLogFile = require("../libs/writeLogFile");

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

            globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished",  true );

            socketIo.emit("module NI API", { 
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": true
                },
            });

            /*
            Запрашиваем ВЕСЬ список источников которые есть в базе
            данных модуля сетевого взаимодействия

            setTimeout(() => {
                console.log("send command \"get an updated list of sources\"");
    
                connModuleNetInteraction.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "get an updated list of sources",
                    taskID: "nv8ej8hd8h8h38c8g49g49",
                    options: {}
                });
            }, 3000);*/
        }).on("message", (msg) => {
            debug("--- MESSAGE ---");
            debug(msg);
        }).on("close", (msg) => {
            debug("--- CONNECTION CLOSE ---");
            debug(msg);

            globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished",  false );

            socketIo.emit("module NI API", { 
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": false
                },
            });
        }).on("information source control", (msg) => {
            debug("----- information source control -----");
            debug(msg);
            debug(msg.options.sl);
            debug("--------------------------------------");

            require("../routes/handlersMsgModuleNetworkInteraction/handlerMsgSources")(msg, socketIo);

        }).on("command source control", (msg) => {
            debug("----- command source control ------");
            debug(msg);
            debug("------------------------------------------");

            //обрабатываем запрос ISEMS-NIH на получение актуального списка источников
            require("./handlersMsgModuleNetworkInteraction/handlerMsgGetNewSourceList")();

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

        }).on("information search control", (msg) => {
            debug("====== information search control =====");
            debug(JSON.stringify(msg));
            /*        msg.options.slft.forEach((item) => {
            debug(item);
        });*/
            debug("=======================================");
        }).on("command information search control", (msg) => {
            debug("====== command information search control =====");
            debug(JSON.stringify(msg));
            /*        msg.options.slft.forEach((item) => {
            debug(item);
        });*/
            debug("=======================================");
        }).on("user notification", (notify) => {
            debug("---- RECEIVED user notification ----");
            debug(notify);

            showNotify({
                socketIo: socketIo,
                type: notify.options.n.t,
                message: `МОДУЛЬ СЕТЕВОГО ВЗАИМОДЕЙСТВИЯ (${notify.options.n.d})`,
            });

        }).on("error", (err) => {
            debug("ERROR MESSAGE");
            debug(err);

            globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished",  false );

            socketIo.emit("module NI API", { 
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": false
                },
            });

            writeLogFile("error", `${err.toString()} (module 'network interaction')`);
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
