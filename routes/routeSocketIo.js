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
    if (!globalObject.hasData("descriptionAPI", "networkInteraction", "connection")) {
        return;
    }

    let connModuleNetInteraction = globalObject.getData("descriptionAPI", "networkInteraction", "connection");

    //обработчик для модуля NetworkInteraction
    connModuleNetInteraction
        .on("connect", (msg) => {
            debug("--- CONNECTION ---");
            debug(msg);

            //globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished", true);

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

                debug("SENS ---> request 'get an updated list of sources'");

                connModuleNetInteraction.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "get an updated list of sources",
                    taskID: helpersFunc.getRandomHex(),
                    options: {}
                });
            }, 3000);
        }).on("message", (msg) => {
            debug("--- MESSAGE ---");
            debug(msg);
        }).on("close", (msg) => {
            debug("--- CONNECTION CLOSE ---");
            debug(msg);

            if (!globalObject.getData("descriptionAPI", "networkInteraction", "previousConnectionStatus")) {
                return;
            }

            //что бы данное сообщение отправилось в UI только раз, после разрува соединения
            socketIo.emit("module NI API", {
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": false
                },
            });

            globalObject.setData("descriptionAPI", "networkInteraction", "previousConnectionStatus", false);
        }).on("information source control", (msg) => {
            debug("----- information source control -----");
            debug(msg);
            debug("--------------------------------------");

            require("./handlers_msg_module_network_interaction/handlerMsgSources")(msg, socketIo);

        }).on("command source control", (msg) => {
            debug("----- command source control ------");
            debug(msg);
            debug("------------------------------------------");

            //обрабатываем запрос ISEMS-NIH на получение актуального списка источников
            require("./handlers_msg_module_network_interaction/handlerMsgGetNewSourceList")();

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

            if (sourceInfo === null) {
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
                }
            });

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
            //debug(JSON.stringify(msg));


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
            if (msg.instruction === "processing get all information by task ID") {
                socketIo.emit("module NI API", {
                    "type": "processingGetAllInformationByTaskID",
                    "options": {
                        status: msg.options.s,
                        taskParameter: msg.options.tp,
                    }
                });
            }

            //получили краткую информацию о всех задачах подходящих под 
            // заданные условия поиска
            if (msg.instruction === "processing information search task") {
                //ищем тип задачи в globalObject.tasks
                if (globalObject.hasData("tasks", msg.taskID)) {
                    let taskInfo = globalObject.getData("tasks", msg.taskID);

                    debug(taskInfo);

                    /**
                     * может быть здесь после поиска удалять задачу из списка
                     */

                    if (taskInfo.eventName === "list all tasks") {
                        debug("received information from event 'list all tasks'");
                        debug(msg.options);

                        require("./route_handlers_socketio/handlerActionsProcessedReceivedListTasks").receivedListAllTasks(socketIo, msg, taskInfo.userSessionID);
                    }

                    //только для вкладки "загрузка файлов" и для виджетов 
                    if (taskInfo.eventName === "list tasks which need to download files") {
                        require("./route_handlers_socketio/handlerActionsProcessedReceivedListTasks").receivedListTasksDownloadFiles(socketIo, msg, taskInfo.userSessionID);
                    }

                    //только для виджета "выгруженные файлы не рассмотрены" и
                    // для вкладки поиск, значение "по умолчанию", выводить список
                    // не закрытых пользователем задач
                    if (taskInfo.eventName === "list unresolved tasks") {
                        require("./route_handlers_socketio/handlerActionsProcessedReceivedListTasks").receivedListUnresolvedTask(socketIo, msg, taskInfo.userSessionID);
                    }

                    /*
                    //только как результат при поиске во вкладке "поиск"
                    if (taskInfo.eventName === "list of found tasks") {
                        debug(msg.options);
                    }
                    */
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

            if (msg.instruction === "processing list files by task ID") {
                debug("received information about file list");

                socketIo.emit("module NI API", {
                    "type": "listFilesByTaskID",
                    "options": msg.options,
                });
            }

            if (msg.instruction === "processing get common analytics information about task ID") {
                debug("RECEIVED processing get common analytics information about task ID");
                debug("-----------------");
                debug(msg.options);
                debug("-----------------");

                socketIo.emit("module NI API", {
                    "type": "commonAnalyticsInformationAboutTaskID",
                    "options": msg.options,
                });
            }

            /*

    },

            msg.options.slft.forEach((item) => {
            debug(item);
        });*/
            debug("=======================================");
        }).on("command information search control", (msg) => {
            debug("====== command information search control =====");

            if (msg.instruction === "delete all information about a task") {
                if (msg.options.ss) {
                    debug("!!! received message success delete information about task !!!");

                    socketIo.emit("module NI API", {
                        "type": "deleteAllInformationAboutTask",
                        "options": {},
                    });
                }
            }

            if (msg.instruction === "mark an task as completed") {
                if (msg.options.ss) {
                    debug("received message SUCCESS mark task complete");
                    debug(msg);

                    socketIo.emit("module NI API", {
                        "type": "successMarkTaskAsCompleted",
                        "options": { "taskID": msg.options.tid },
                    });
                }
            }

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
            require("./handlers_msg_module_network_interaction/handlerMsgNotification")(notify);
        }).on("error", (err) => {
            debug("ERROR MESSAGE");
            debug(err);


            if (!globalObject.getData("descriptionAPI", "networkInteraction", "previousConnectionStatus")) {
                return;
            }

            //что бы данное сообщение отправилось в UI только раз, после разрува соединения
            socketIo.emit("module NI API", {
                "type": "connectModuleNI",
                "options": {
                    "connectionStatus": false
                },
            });

            globalObject.setData("descriptionAPI", "networkInteraction", "previousConnectionStatus", false);
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
    require("./route_handlers_socketio/handlerChangePassword")(socketIo);

    /* --- УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ --- */
    require("./route_handlers_socketio/handlerActionsUsers").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ГРУППАМИ --- */
    require("./route_handlers_socketio/handlerActionsGroups").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ОРГАНИЗАЦИЯМИ, ПОДРАЗДЕЛЕНИЯМИ И ИСТОЧНИКАМИ --- */
    require("./route_handlers_socketio/handlerActionsOrganizationsAndSources").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ПРАВИЛАМИ СОА --- sid_soa:find sid */
    require("./route_handlers_socketio/handlerActionRulesSOA").addHandlers(socketIo);

    /* --- УПРАВЛЕНИЕ ЗАГРУЗКОЙ ФАЙЛОВ ПОЛУЧАЕМЫХ С User Interface --- */
    require("./route_handlers_socketio/handlerActionUploadFiles").addHandlers(ss, socketIo);

    /* --- УПРАВЛЕНИЕ ЗАДАЧАМИ ПО ФИЛЬТРАЦИИ ФАЙЛОВ --- */
    require("./route_handlers_socketio/handlerActionsFiltrationTask").addHandlers(socketIo);

    /* --- ПОЛУЧИТЬ ИНФОРМАЦИЮ О ЗАДАЧАХ ВЫПОЛНЯЕМЫХ МОДУЛЕМ СЕТЕВОГО ВЗАИМОДЕЙСТВИЯ --- */
    require("./route_handlers_socketio/networkInteractionHandlerRequestShowTaskInfo").addHandlers(socketIo);

    /* --- ОБРАБОТЧИК ДЕЙСТВИЙ ПРИ СКАЧИВАНИИ ФАЙЛОВ, В ТОМ ЧИСЛЕ ЗАПРОС СПИСКА ЗАДАЧ (пагинатор) --- */
    require("./route_handlers_socketio/handlerActionsDownloadingTasks").addHandlers(socketIo);

    /* --- ПОЛУЧИТЬ ИНФОРМАЦИЮ ИЗ ЖУРНАЛА ИНФОРМАЦИОННЫХ СООБЩЕНИЙ --- */
    require("./route_handlers_socketio/networkInteractionHandlerNotificationLog").addHandlers(socketIo);
};