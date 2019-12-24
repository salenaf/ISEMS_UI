/*
 * Маршруты для обработки информации передаваемой через протокол socket.io
 *
 * Версия 0.1, дата релиза 14.02.2019
 * */

"use strict";

const debug = require("debug")("routeSocketIo");

const fs = require("fs");
const path = require("path");
const validate = require("validate.js");

const objGlobals = require("../configure/globalObject");
const showNotify = require("../libs/showNotify");
const writeLogFile = require("../libs/writeLogFile");
const getSessionId = require("../libs/helpers/getSessionId");
const checkStatusSource = require("../libs/processing/status_source/checkStatusSource");
const handlerActionsUsers = require("./routeHandlersSocketIo/handlerActionsUsers");
const checkUserAuthentication = require("../libs/check/checkUserAuthentication");
//const checkLimitNumberRequestsSocketIo = require('../libs/check/checkLimitNumberRequestsSocketIo');

const managemetGroups = require("./pages/processing_socketio_request/element_settings/managementGroup");

//генератор событий (обрабатывает события от внешних источников, например API)
exports.eventGenerator = function(socketIo, object) {
    let actionsObject = {
        "waterfall-broker": {
            "API": {
                "connect": function() {
                    //отправляем информационное сообщение
                    showNotify(socketIo, "success", "Установлено соединение с API waterfall-broker");
                    //генерируем событие изменяющее статус соединения с waterfall-broker
                    socketIo.emit("change of status", {
                        source: "waterfall-broker",
                        type: "API",
                        currentStatus: "connect"
                    });
                },
                "connect error": function() {
                    //устанавливаем статус соединения для всех источников в 'не подключен'
                    setDisconnectSourceAll();

                    //генерируем событие об изменении статусов соединения
                    checkStatusSource(socketIo);
                    showNotify(socketIo, "danger", "Невозможно установить соединение с API waterfall-broker");
                    //генерируем событие изменяющее статус соединения с waterfall-broker
                    socketIo.emit("change of status", {
                        source: "waterfall-broker",
                        type: "API",
                        currentStatus: "error"
                    });
                },
                "disconnect": function() {
                    //устанавливаем статус соединения для всех источников в 'не подключен'
                    setDisconnectSourceAll();

                    //генерируем событие об изменении статусов соединения
                    checkStatusSource(socketIo);
                    showNotify(socketIo, "warning", "Соединение с API waterfall-broker было разорвано");
                    //генерируем событие изменяющее статус соединения с waterfall-broker
                    socketIo.emit("change of status", {
                        source: "waterfall-broker",
                        type: "API",
                        currentStatus: "disconnect"
                    });
                },
                "new message": function() {
                    if (object.info.message.type === "status message") {
                        let sourceId = +object.info.message.information.sourceId;

                        if (!validate.isNumber(sourceId)) return;
                        if (object.info.message.information.statusProcess !== "successfully") return;

                        if (typeof objGlobals.sources.sourceAvailability[sourceId] === "undefined") {
                            return writeLogFile("info", "the source has not been added to database");
                        }
                        objGlobals.sources.sourceAvailability[sourceId].dateLastUpdate = +new Date();
                        objGlobals.sources.sourceAvailability[sourceId].statusNew = true;
                    }
                }
            }
        },
        "waterfall-worker": {
            "API": {
                "connect": function() {
                    //отправляем информационное сообщение
                    showNotify(socketIo, "success", "Установлено соединение с API waterfall-worker");
                    //генерируем событие изменяющее статус соединения с waterfall-broker
                    socketIo.emit("change of status", {
                        source: "waterfall-worker",
                        type: "API",
                        currentStatus: "connect"
                    });
                },
                "connect error": function() {
                    showNotify(socketIo, "danger", "Невозможно установить соединение с API waterfall-worker");
                    //генерируем событие изменяющее статус соединения с waterfall-broker
                    socketIo.emit("change of status", {
                        source: "waterfall-worker",
                        type: "API",
                        currentStatus: "error"
                    });
                },
                "disconnect": function() {
                    showNotify(socketIo, "warning", "Соединение с API waterfall-worker было разорвано");
                    //генерируем событие изменяющее статус соединения с waterfall-broker
                    socketIo.emit("change of status", {
                        source: "waterfall-worker",
                        type: "API",
                        currentStatus: "disconnect"
                    });
                },
                "new message": function() {
                    //if (object.info.message.type === "status message") {}
                }
            }
        }
    };

    let nameIsExist = (typeof actionsObject[object.name] === "undefined");
    let typeIsExist = (typeof actionsObject[object.name][object.type] === "undefined");
    let infoIsExist = (typeof actionsObject[object.name][object.type][object.info.action] === "undefined");

    if (nameIsExist || typeIsExist || infoIsExist) return;

    actionsObject[object.name][object.type][object.info.action]();
};

//генератор событий
exports.eventEmitter = function(socketIo, object) {
    let handling = {
        "changingStatusSource": checkStatusSource.bind(null, socketIo)
    };

    console.log("--- script:routeSocketIo, Event Emitter ---");

    handling[object.type]();
};

/** 
 * ОБРАБОТЧИК СОБЫТИЙ ПОСТУПАЮЩИХ С User Interface 
 * 
 **/
module.exports.eventHandling = function(socketIo) {
    /* --- УПРАВЛЕНИЕ ПАРОЛЯМИ ПО УМОЛЧАНИЮ --- */
    require("./routeHandlersSocketIo/handlerChangePassword")(socketIo);

    /* --- УПРАВЛЕНИЕ ГРУППАМИ --- */

    // добавление новой группы
    socketIo.on("add new group", data => {

        debug("ADDITION NEW GROUP");
        debug(data);

        //проверка авторизован ли пользователь
        checkUserAuthentication(socketIo)
            .then(authenticationData => {
                if (authenticationData.isAuthorization) {
                    return false;
                }

                if (!authenticationData.document.group_settings.management_groups.element_settings.create.status) {
                    return false;
                }

                return true;
            }).then(isSuccess => {
                if (!isSuccess) {
                    showNotify(socketIo, "danger", "Невозможно добавить группу, недостаточно прав на выполнение данного действия.");

                    return;
                }

                managemetGroups(data, (err, processingResult) => {
                    if (err) throw (err);

                    if (processingResult.isProcessed) {
                        showNotify(socketIo, "success", "Группа успешно добавлена.");
                    } else {
                        showNotify(socketIo, "danger", processingResult.messageError);
                    }
                });
            }).catch(err => {

                debug(err);

                showNotify(socketIo, "danger", "Ошибка сервера, выполнение действия невозможно.");

                return writeLogFile("error", err.toString());
            });
    });

    /* --- УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ --- */
    handlerActionsUsers.addHandlers(socketIo);

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

//изменение статуса на 'не подключен' для всех источников
function setDisconnectSourceAll() {
    for (let sourceId in objGlobals.sources.sourceAvailability) {
        objGlobals.sources.sourceAvailability[sourceId].statusOld = false;
        objGlobals.sources.sourceAvailability[sourceId].statusNew = false;
    }
}