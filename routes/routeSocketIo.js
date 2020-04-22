"use strict";

const debug = require("debug")("routeSocketIo");

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

    /**
     * "rules soa", {
            "actionType": "search",
            "options": {
                "sid": this.state.filter_search
            },
     */

    socketIo.on("rules soa", (msg) => {
        console.log("---- RESEIVED MSG 'rules soa' ---");
        console.log(msg);

        socketIo.emit("rules soa", { mes: "many message !!!!" });
    });

    /* --- РЕШАЮЩИЕ ПРАВИЛА СОА --- */
    /* удаление решающих правил СОА */
    socketIo.on("delete rules ids", function(data) {
        //только выбранных правил
        if (data.processingType === "drop change class") {
            //проверяем авторизован ли пользователь
            require("../libs/check/checkUserAuthentication")(socketIo, function(err, isAuthorization) {
                if (err) {
                    writeLogFile("error", err.toString());
                    showNotify(socketIo, "danger", "Ошибка обработки запроса");
                    return;
                }

                if (!isAuthorization) return writeLogFile("error", "the user is not authorized");

                getSessionId("socketIo", socketIo, (err, sessionId) => {
                    if (err) {
                        writeLogFile("error", err.toString());
                        showNotify(socketIo, "danger", "Некорректный идентификатор сессии");
                        return;
                    }
                    //проверяем имеет ли пользователь права на загрузку файлов
                    require("../libs/check/checkAccessRightsExecute")({
                        management: "management_ids_rules",
                        actionType: "delete",
                        sessionId: sessionId
                    }, function(err, successfully) {
                        if (err) {
                            writeLogFile("error", err.toString());
                            showNotify(socketIo, "danger", "Ошибка обработки запроса");
                            return;
                        }

                        if (!successfully) {
                            writeLogFile("error", "not enough rights to perform the action (session ID: " + socketIo.sessionID + ")");
                            showNotify(socketIo, "danger", "Недостаточно прав для выполнения действия");
                        } else {
                            require("../libs/processing/routeSocketIo/deleteIdsRules")("drop change class", data.options, socketIo, (err, message) => {
                                if (err) {
                                    writeLogFile("error", err.toString());
                                    showNotify(socketIo, "danger", "Ошибка обработки запроса");
                                } else {
                                    socketIo.emit("uploaded files", {
                                        processing: "delete",
                                        typeFile: "ids rules"
                                    });
                                }
                            });
                        }
                    });
                });
            });
        }
        //всех решающих правил
        if (data.processingType === "drop data base") {
            //проверяем авторизован ли пользователь
            require("../libs/check/checkUserAuthentication")(socketIo, function(err, isAuthorization) {
                if (err) {
                    writeLogFile("error", err.toString());
                    showNotify(socketIo, "danger", "Ошибка обработки запроса");
                    return;
                }

                if (!isAuthorization) return writeLogFile("error", "the user is not authorized");

                getSessionId("socketIo", socketIo, (err, sessionId) => {
                    if (err) {
                        writeLogFile("error", err.toString());
                        showNotify(socketIo, "danger", "Некорректный идентификатор сессии");
                        return;
                    }
                    //проверяем имеет ли пользователь права на загрузку файлов
                    require("../libs/check/checkAccessRightsExecute")({
                        management: "management_ids_rules",
                        actionType: "delete",
                        sessionId: sessionId
                    }, function(err, successfully) {
                        if (err) {
                            writeLogFile("error", err.toString());
                            showNotify(socketIo, "danger", "Ошибка обработки запроса");
                            return;
                        }

                        if (!successfully) {
                            writeLogFile("error", "not enough rights to perform the action (session ID: " + socketIo.sessionID + ")");
                            showNotify(socketIo, "danger", "Недостаточно прав для выполнения действия");
                        } else {
                            require("../libs/processing/routeSocketIo/deleteIdsRules")("drop data base", {}, socketIo, (err) => {
                                if (err) {
                                    writeLogFile("error", err.toString());
                                    showNotify(socketIo, "danger", "Ошибка обработки запроса");
                                } else {
                                    socketIo.emit("uploaded files", {
                                        processing: "delete",
                                        typeFile: "ids rules"
                                    });
                                }
                            });
                        }
                    });
                });
            });
        }
    });

    //поиск решающих правил по выбранным идентификаторам
    socketIo.on("search rules sid", function(data) {
        //проверяем авторизован ли пользователь
        require("../libs/check/checkUserAuthentication")(socketIo, function(err, isAuthorization) {
            if (err) {
                writeLogFile("error", err.toString());
                showNotify(socketIo, "danger", "Ошибка обработки запроса");
                return;
            }

            if (!isAuthorization) return writeLogFile("error", "the user is not authorized");

            getSessionId("socketIo", socketIo, (err, sessionId) => {
                if (err) {
                    writeLogFile("error", err.toString());
                    showNotify(socketIo, "danger", "Некорректный идентификатор сессии");
                    return;
                }
                //проверяем имеет ли пользователь права на загрузку файлов
                require("../libs/check/checkAccessRightsExecute")({
                    management: "management_ids_rules",
                    actionType: "read",
                    sessionId: sessionId
                }, function(err, successfully) {
                    if (err) {
                        writeLogFile("error", err.toString());
                        showNotify(socketIo, "danger", "Ошибка обработки запроса");
                        return;
                    }

                    if (!successfully) {
                        writeLogFile("error", "not enough rights to perform the action (session ID: " + socketIo.sessionID + ")");
                        showNotify(socketIo, "danger", "Недостаточно прав для выполнения действия");
                    } else {
                        require("../libs/processing/routeSocketIo/searchAdditionalInformationSidIdsRules")(data, (err, result) => {
                            if (err) {
                                writeLogFile("error", err.toString());
                                showNotify(socketIo, "danger", "Ошибка обработки запроса");
                            } else {
                                socketIo.emit("search for sid ids", {
                                    processing: "completed",
                                    information: result
                                });
                            }
                        });
                    }
                });
            });
        });
    });

    //получить дополнительную информацию по массиву идентификаторов решающих правил СОА
    socketIo.on("get additional information for sid", function(data) {
        //проверяем авторизован ли пользователь
        require("../libs/check/checkUserAuthentication")(socketIo, function(err, isAuthorization) {
            if (err) {
                writeLogFile("error", err.toString());
                showNotify(socketIo, "danger", "Ошибка обработки запроса");
                return;
            }

            if (!isAuthorization) return writeLogFile("error", "the user is not authorized");

            require("../libs/processing/routeSocketIo/searchAdditionalInformationSidIdsRules")(data, function(err, document) {
                if (err) {
                    writeLogFile("error", err.toString());
                    showNotify(socketIo, "danger", "Ошибка обработки запроса");
                } else {
                    socketIo.emit("additional information for sid", {
                        information: document
                    });
                }
            });
        });
    });


    // получаем данные об источнике для дачборда главной страницы все кроме КА 
    /*    socketIo.on('get source information for dashboard', function(data) {
            require('../libs/check/checkUserAuthorization')(socketIo, function(err, isAuthorization) {
                if (err) {
                    writeLogFile('error', err.toString());
                    showNotify(socketIo, 'danger', 'Ошибка обработки запроса');
                    return;
                }

                if (!isAuthorization) return writeLogFile('error', 'the user is not authorized');
                //проверяем на привышение количества запросов выполненных одним пользоваталем по одному типу запросов
                if (!checkLimitNumberRequestsSocketIo(socketIo, 'get source information for dashboard')) {
                    showNotify(socketIo, 'danger', 'Для пользователя превышен лимит запросов, попробуйте выполнить запрос позже');
                    return;
                }

                //добавляем в коллекцию 'session.user.informations' новый источник
                require('../libs/processing/changeUserSettings').addNewDashboardSource(socketIo, data);

                //добавляем в коллекцию 'users' новый источник
                require('../libs/processing/changeUserSettings').changeCollectionUsersUserSettings('add', socketIo, data);

            });
        });

        // получаем данные для дачборда по КА 
        socketIo.on('get source information for dashboard attack', function(data) {
            require('../libs/check/checkUserAuthorization')(socketIo, function(err, isAuthorization) {
                if (err) {
                    writeLogFile('error', err.toString());
                    showNotify(socketIo, 'danger', 'Ошибка обработки запроса');
                    return;
                }

                if (!isAuthorization) return writeLogFile('error', 'the user is not authorized');
                //проверяем на привышение количества запросов выполненных одним пользоваталем по одному типу запросов
                if (!checkLimitNumberRequestsSocketIo(socketIo, 'get source information for dashboard')) {
                    showNotify(socketIo, 'danger', 'Для пользователя превышен лимит запросов, попробуйте выполнить запрос позже');
                    return;
                }
            });
        });

        // удаление источника с панели дачборда главной страницы
        socketIo.on('delete source id dashboard', function(data) {
            require('../libs/check/checkUserAuthorization')(socketIo, function(err, isAuthorization) {
                if (err) {
                    writeLogFile('error', err.toString());
                    showNotify(socketIo, 'danger', 'Ошибка обработки запроса');
                    return;
                }

                if (!isAuthorization) return writeLogFile('error', 'the user is not authorized');

                //удаляем источник из настроек пользователя
                require('../libs/processing/changeUserSettings').deleteDashboardSource(socketIo, data);

                //удаляем из коллекцию users выбранный источник
                require('../libs/processing/changeUserSettings').changeCollectionUsersUserSettings('delete', socketIo, data);

            });
        });*/
};

/* --- УПРАВЛЕНИЕ ЗАГРУЗКОЙ ФАЙЛОВ --- */
exports.uploadFiles = function(socketIo, ss) {
    //проверяем авторизован ли пользователь
    checkUserAuthentication(socketIo, function(err, isAuthorization) {
        if (err) {
            writeLogFile("error", err.toString());
            showNotify(socketIo, "danger", "Ошибка обработки запроса");
            return;
        }

        if (!isAuthorization) return writeLogFile("error", "the user is not authorized");

        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) {
                writeLogFile("error", err.toString());
                showNotify(socketIo, "danger", "Некорректный идентификатор сессии");
                return;
            }

            /* загрузка файла с решающими правилами СОА */
            ss(socketIo).on("upload file rules IDS", function(stream, data) {
                //проверяем имеет ли пользователь права на загрузку файлов
                require("../libs/check/checkAccessRightsExecute")({
                    management: "management_ids_rules",
                    actionType: "create",
                    sessionId: sessionId
                }, function(err, successfully) {
                    if (err) {
                        writeLogFile("error", err.toString());
                        showNotify(socketIo, "danger", "Ошибка обработки запроса");
                        return;
                    }

                    if (!successfully) {
                        writeLogFile("error", "not enough rights to perform the action (session ID: " + socketIo.sessionID + ")");
                        showNotify(socketIo, "danger", "Недостаточно прав для выполнения действия");
                    } else {
                        let fileName = (__dirname.substr(0, (__dirname.length - 6)) + "uploads/") + path.basename(data.name);
                        let tempFile = fs.createWriteStream(fileName, { flags: "w", defaultEncoding: "utf8", autoClose: true });
                        stream.pipe(tempFile);

                        tempFile.on("close", function() {
                            require("../libs/check/checkUserAuthentication")(socketIo, function(err, isAuthorization) {
                                if (err) {
                                    writeLogFile("error", err.toString());
                                    showNotify(socketIo, "danger", "Ошибка обработки запроса");
                                    return;
                                }

                                if (!isAuthorization) return writeLogFile("error", "the user is not authorized");

                                showNotify(socketIo, "success", "Файл '" + data.name + "' успешно загружен");

                                let pathFolder = (__dirname.substr(0, (__dirname.length - 6)) + "uploads/");
                                require("../libs/processing/processing_uploaded_files/processingUploadRuleFileIDS")(socketIo, data.name, pathFolder, function(err, countRules) {
                                    if (err) return showNotify(socketIo, "danger", "Получен некорректный файл");

                                    writeLogFile("info", "file '" + data.name + "' was successfully processed");
                                    showNotify(socketIo, "success", "Обновление решающих правил СОА выполнено успешно, добавлено " + countRules + " правил");
                                });
                            });
                        });
                    }
                });
            });

            /* загрузка информации о настройках источников (файл в формате XML) */
            ss(socketIo).on("upload file sources setting", function(stream, data) {
                //проверяем имеет ли пользователь права на загрузку файлов
                require("../libs/check/checkAccessRightsExecute")({
                    management: "management_sources",
                    actionType: "create",
                    sessionId: sessionId
                }, function(err, successfully) {
                    if (err) {
                        writeLogFile("error", err.toString());
                        showNotify(socketIo, "danger", "Ошибка обработки запроса");

                        return;
                    }

                    if (!successfully) {
                        writeLogFile("error", "not enough rights to perform the action (session ID: " + socketIo.sessionID + ")");
                        showNotify(socketIo, "danger", "Недостаточно прав для выполнения действия");

                        return;
                    }

                    let fileName = (__dirname.substr(0, (__dirname.length - 6)) + "uploads/") + path.basename(data.name);
                    let tempFile = fs.createWriteStream(fileName, { flags: "w", defaultEncoding: "utf8", autoClose: true });
                    stream.pipe(tempFile);

                    tempFile.on("close", function() {
                        require("../libs/processing/processing_uploaded_files/processingUploadFileSourceSetting")(fileName, function(err, objCountUploaded) {
                            if (err) {
                                writeLogFile("error", err.toString());
                                showNotify(socketIo, "danger", "Ошибка обработки загруженного файла");
                            } else {
                                let messageLog = "the information update performed by the user with a username of administrator,";
                                messageLog += " a number of processed data is updated / not updated " + objCountUploaded.countUpdate + "/" + objCountUploaded.countOverlap;
                                writeLogFile("info", messageLog);

                                let message = "Импорт информации по источникам успешно выполнен, всего обработано ";
                                message += (objCountUploaded.countUpdate + objCountUploaded.countOverlap) + " из них добавлено " + objCountUploaded.countUpdate;

                                showNotify(socketIo, "success", message);
                                socketIo.emit("action page", { reload: true });
                            }
                        });
                    });
                });
            });
        });
    });
};
