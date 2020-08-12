"use strict";

const debug = require("debug")("routeSocketIo");

const ss = require("socket.io-stream");

const showNotify = require("../libs/showNotify");
const helpersFunc = require("../libs/helpers/helpersFunc");
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




    /** ТЕСТОВЫЙ РАЗДЕЛ --- начало */
    function testProcessDownload(filePath, callback){
        console.log(`чтение файла: ${filePath}`);

        const fs = require("fs");
        const EventEmitter = require("events");

        class MyEmitter extends EventEmitter {}

        new Promise((resolve, reject) => {
            fs.readFile(filePath, "utf8", (err, data) => {
                if(err){
                    reject(err);
                }

                resolve(data);
            });
        }).then((data) => {
            let stringList = data.split("\n");

            console.log(stringList.length);

            let count = 0;
            let listFilterProcess = [];
            stringList.forEach((item) => {
                if(item.length > 0){
                    let objTmp = JSON.parse(item);

                    //только для процесса скачивания файлов
                    if(objTmp.instruction === "task processing" && (typeof objTmp.options.dfi !== "undefined")){
                        count++;
                        listFilterProcess.push(item);
                    }
                }
            });

            //console.log(data);

            return { count: count, list: listFilterProcess };
        }).then((obj) => {
            const myEmitter = new MyEmitter();

            let numInterval = 0;
            let timerID = setInterval(() => {
                if(numInterval === (obj.count - 1)){
                    clearInterval(timerID);

                    myEmitter.emit("finish", {});
                }

                //console.log(`received next emit, num: ${numInterval}`);
                //console.log(obj.list[numInterval]);

                let objTmp = JSON.parse(obj.list[numInterval]);
                myEmitter.emit("next emit", { 
                    "type": "downloadProcessing",
                    "options": {
                        sourceID: objTmp.options.id,
                        name: "shortName",
                        taskID: objTmp.taskID,
                        taskIDModuleNI: objTmp.options.tidapp,
                        status: objTmp.options.s,
                        parameters: {
                            numberFilesTotal: objTmp.options.nft, //общее количество скачиваемых файлов
                            numberFilesDownloaded: objTmp.options.nfd, //количество успешно скаченных файлов
                            numberFilesDownloadedError: objTmp.options.nfde, //количество файлов скаченных с ошибкой
                            dfi: { //DetailedFileInformation — подробная информация о скачиваемом файле
                                fileName: objTmp.options.dfi.n, //название файла
                                fullSizeByte: objTmp.options.dfi.fsb, //полный размер файла в байтах
                                acceptedSizeByte: objTmp.options.dfi.asb, //скаченный размер файла в байтах
                                acceptedSizePercent: objTmp.options.dfi.asp, //скаченный размер файла в процентах
                            }
                        },
                    }});                    

                numInterval++;
            }, 500);

            callback(null, { 
                count: obj.count, 
                list: obj.list,
                myEmitter: myEmitter,
            });
        }).catch((err) => {
            callback(err);
        });
    }

    function testProcessFiltering(filePath, callback) {
        console.log(`чтение файла: ${filePath}`);

        const fs = require("fs");
        const EventEmitter = require("events");

        class MyEmitter extends EventEmitter {}

        new Promise((resolve, reject) => {
            fs.readFile(filePath, "utf8", (err, data) => {
                if(err){
                    reject(err);
                }

                resolve(data);
            });
        }).then((data) => {
            let stringList = data.split("\n");

            console.log(stringList.length);

            let count = 0;
            let listFilterProcess = [];
            stringList.forEach((item) => {
                if(item.length > 0){
                    let objTmp = JSON.parse(item);

                    //только для процесса фильтрации
                    if(objTmp.instruction === "task processing" && (typeof objTmp.options.ffi !== "undefined")){
                        count++;
                        listFilterProcess.push(item);
                    }
                }
            });

            //console.log(data);

            return { count: count, list: listFilterProcess };
        }).then((obj) => {
            const myEmitter = new MyEmitter();

            let numInterval = 0;
            let timerID = setInterval(() => {
                if(numInterval === (obj.count - 1)){
                    clearInterval(timerID);

                    myEmitter.emit("finish", {});
                }

                //console.log(`received next emit, num: ${numInterval}`);
                //console.log(obj.list[numInterval]);

                let objTmp = JSON.parse(obj.list[numInterval]);
                myEmitter.emit("next emit", { 
                    "type": "filtrationProcessing",
                    "options": {
                        sourceID: objTmp.options.id,
                        name: "shortName",
                        taskID: objTmp.taskID,
                        taskIDModuleNI: objTmp.options.tidapp,
                        status: objTmp.options.s,
                        parameters: {
                            numDirectoryFiltration: objTmp.options.ndf,
                            numAllFiles: objTmp.options.nfmfp,
                            numProcessedFiles: objTmp.options.npf,
                            numProcessedFilesError: objTmp.options.nepf,
                            numFindFiles: objTmp.options.nffrf,
                            sizeAllFiles: objTmp.options.sfmfp,
                            sizeFindFiles: objTmp.options.sffrf,
                        },
                    }});                    

                numInterval++;
            }, 500);

            callback(null, { 
                count: obj.count, 
                list: obj.list,
                myEmitter: myEmitter,
            });
        }).catch((err) => {
            callback(err);
        });
    }

    setTimeout(() => {
        testProcessFiltering("/home/development/modul_api_interaction/information_response_1589542887119.txt", (err, obj) => {
            debug("запуск тестовый функции");
            if(err){
                debug(err);
            }

            obj.myEmitter.on("next emit", (data) => {
    
                //console.log(data);
                socketIo.emit("module NI API", data);
    
            }).on("finish", () => {
                debug(`received event 'finish' (${new Date})`);
            });
        });
    }, 3000);

    setTimeout(() => {
        testProcessFiltering("/home/development/modul_api_interaction/information_response_1590584597947.txt", (err, obj) => {
            if(err){
                debug(err);
            }
            
            obj.myEmitter.on("next emit", (data) => {
                socketIo.emit("module NI API", data);
            }).on("finish", () => {
                debug(`received event 'finish' (${new Date})`);    
            });
        });
    }, 6000);

    setTimeout(() => {
        testProcessDownload("/home/development/modul_api_interaction/information_download_control_23.12.2019.log.txt", (err, obj) => {
            if(err){
                debug(err);
            }

            obj.myEmitter.on("next emit", (data) => {
                socketIo.emit("module NI API", data);
            }).on("finish", () => {
                debug(`received event 'finish' (${new Date})`);    
            });
        });
    }, 8000);
    /** ТЕСТОВЫЙ РАЗДЕЛ --- окончание */




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
            данных модуля сетевого взаимодействия, что бы получить 
            актуальный список и в том числе статусы сетевых 
            соединений источников
            */
            setTimeout(() => {
                connModuleNetInteraction.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "get an updated list of sources",
                    taskID: helpersFunc.getRandomHex(),
                    options: {}
                });
            }, 1000);
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
            //debug(msg.options.sl);
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

            let sourceInfo = globalObject.getData("sources", msg.options.id);
            //формируем сообщение о выполнении процесса фильтрации
            socketIo.emit("module NI API", { 
                "type": "filtrationProcessing",
                "options": {
                    sourceID: msg.options.id,
                    name: sourceInfo.shortName,
                    taskID: msg.taskID,
                    taskIDModuleNI: msg.options.tidapp,
                    status: msg.options.s,
                    parameters: {
                        numDirectoryFiltration: msg.options.ndf,
                        numAllFiles: msg.options.nfmfp,
                        numProcessedFiles: msg.options.npf,
                        numProcessedFilesError: msg.options.nepf,
                        numFindFiles: msg.options.nffrf,
                        sizeAllFiles: msg.options.sfmfp,
                        sizeFindFiles: msg.options.sffrf,
                    },
                },
            });
        }).on("command filtration control", (msg) => {
            /*debug("----- command filtration control -----");
            debug(msg);
            debug("---------------------------------------");*/

        }).on("information download control", (msg) => {
            debug("----- information download control -----");
            debug(msg);
            debug("----------------------------------------");

            let sourceInfo = globalObject.getData("sources", msg.options.id);

            debug("****************************");            
            debug(sourceInfo);
            debug("****************************");

            if(sourceInfo === null){
                return;
            }

            //формируем сообщение о выполнении процесса скачивания файлов
            socketIo.emit("module NI API", { 
                "type": "downloadProcessing",
                "options": {
                    sourceID: msg.options.id,
                    name: sourceInfo.shortName,
                    taskID: msg.taskID,
                    taskIDModuleNI: msg.options.tidapp,
                    status: msg.options.s,
                    parameters: {
                        numberFilesTotal: msg.options.nft, //общее количество скачиваемых файлов
                        numberFilesDownloaded: msg.options.nfd, //количество успешно скаченных файлов
                        numberFilesDownloadedError: msg.options.nfde, //количество файлов скаченных с ошибкой
                        dfi: { //DetailedFileInformation — подробная информация о скачиваемом файле
                            fileName: msg.options.dfi.n, //название файла
                            fullSizeByte: msg.options.dfi.fsb, //полный размер файла в байтах
                            acceptedSizeByte: msg.options.dfi.asb, //скаченный размер файла в байтах
                            acceptedSizePercent: msg.options.dfi.asp, //скаченный размер файла в процентах
                        }
                    },
                }});

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

            let createDate = 0,
                typeTask = "нет данных",
                userLogin = "нет данных",
                userName = "нет данных";

            /* при получении информации о задаче по ее ID проверяем 
             надо ли востановить информацию о задаче в globalObject */
            /*if(globalObject.hasData("tasks", "networkInteractionTaskList", msg.options.tp.ctid)){
                let taskInfo = globalObject.getData("tasks", "networkInteractionTaskList", msg.options.tp.ctid);
                createDate = taskInfo.createDate;
                typeTask = taskInfo.typeTask;
                userLogin = taskInfo.userLogin;
                userName = taskInfo.userName;

                console.log(`User login: ${taskInfo.userLogin}`);
            }

            console.log(`task ID '${msg.taskID}' is found: '${globalObject.hasData("tasks", "networkInteractionTaskList", msg.options.tp.ctid)}'`);
            */

            //получили всю информацию о задаче по ее ID
            if(msg.instruction === "processing get all information by task ID"){
                socketIo.emit("module NI API", { 
                    "type": "processingGetAllInformationByTaskID",
                    "options": {
                        typeTask: typeTask,
                        userLogin: userLogin,
                        userName: userName,
                        createDate: createDate,
                        status: msg.options.s,
                        taskParameter: msg.options.tp,
                    }
                });
            }

            //получили краткую информацию о всех задачах подходящих под 
            //заданные условия поиска
            if(msg.instruction === "processing information search task"){
                //ищем тип задачи в globalObject.tasks
                if(globalObject.hasData("tasks", msg.taskID)){
                    let taskInfo = globalObject.getData("tasks", msg.taskID);

                    //только для вкладки "загрузка файлов" и для виджетов 
                    if(taskInfo.eventName === "list tasks which need to download files"){
                        require("./routeHandlersSocketIo/handlerActionsProcessedReceivedListTasks").receivedListTasksDownloadFiles(socketIo, msg, taskInfo.userSessionID);
                    }

                    //только как результат при поиске во вкладке "поиск"
                    if(taskInfo.eventName === "list of found tasks"){

                    }
                } else {
                    socketIo.emit("module NI API", { 
                        "type": msg.instruction,
                        "options": msg.options,
                        /*typeTask: typeTask,
            userLogin: userLogin,
            userName: userName,
            createDate: createDate,
            status: msg.options.s,
            taskParameter: msg.options.tp,*/
                    });
                }
            }

            if(msg.instruction === "processing list files by task ID"){
                debug("received information about file list");

                socketIo.emit("module NI API", {
                    "type": "listFilesByTaskID",
                    "options": msg.options,
                });
            }
            /*        msg.options.slft.forEach((item) => {
            debug(item);
        });*/
            debug("=======================================");
        }).on("command information search control", (msg) => {
            debug("====== command information search control =====");
            //debug(JSON.stringify(msg));
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

            //записываем сообщение в БД
            require("./handlersMsgModuleNetworkInteraction/handlerMsgNotification")(notify);
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

    /* --- УПРАВЛЕНИЕ ЗАДАЧАМИ ПО ФИЛЬТРАЦИИ ФАЙЛОВ --- */
    require("./routeHandlersSocketIo/handlerActionsFiltrationTask").addHandlers(socketIo);

    /* --- ПОЛУЧИТЬ ИНФОРМАЦИЮ О ЗАДАЧАХ ВЫПОЛНЯЕМЫХ МОДУЛЕМ СЕТЕВОГО ВЗАИМОДЕЙСТВИЯ --- */
    require("./routeHandlersSocketIo/networkInteractionHandlerRequestShowTaskInfo").addHandlers(socketIo);

    /* --- ОБРАБОТЧИК ДЕЙСТВИЙ ПРИ СКАЧИВАНИИ ФАЙЛОВ, В ТОМ ЧИСЛЕ ЗАПРОС СПИСКА ЗАДАЧ (пагинатор) --- */
    require("./routeHandlersSocketIo/handlerActionsDownloadingTasks").addHandlers(socketIo);

    /* --- ПОЛУЧИТЬ ИНФОРМАЦИЮ ИЗ ЖУРНАЛА ИНФОРМАЦИОННЫХ СООБЩЕНИЙ --- */
    require("./routeHandlersSocketIo/networkInteractionHandlerNotificationLog").addHandlers(socketIo);
};
