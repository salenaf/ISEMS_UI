"use strict";

const debug = require("debug")("scmni");

const MyError = require("../../helpers/myError");
const helpersFunc = require("../../helpers/helpersFunc");
const getSessionId = require("../../helpers/getSessionId");
const globalObject = require("../../../configure/globalObject");

/** ---  УПРАВЛЕНИЕ ИСТОЧНИКАМИ --- **/

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * управление удаленными источниками.
 * 
 * Выполняет добавление новых источников в базу данных модуля. 
 * 
 * @param {*} sourceList - список источников
 */
module.exports.sourceManagementsAdd = function(sourceList) {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let list = sourceList.map((item) => {
                let sourceID = +(item.source_id);
                let architecture = (item.source_settings.type_architecture_client_server === "server") ? true : false;
                let telemetry = (item.source_settings.transmission_telemetry === "on");

                sources.push(sourceID);

                return {
                    id: sourceID,
                    at: "add",
                    arg: {
                        ip: item.network_settings.ipaddress,
                        t: item.network_settings.token_id,
                        sn: item.short_name,
                        d: item.description,
                        s: {
                            as: architecture,
                            p: +(item.network_settings.port),
                            et: telemetry,
                            mcpf: +(item.source_settings.maximum_number_simultaneous_filtering_processes),
                            sf: item.source_settings.list_directories_with_file_network_traffic,
                            tan: item.source_settings.type_channel_layer_protocol,
                        },
                    }
                };
            });

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");

            if (conn !== null) {
                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: helpersFunc.getRandomHex(),
                    options: { sl: list },
                });
            }

            resolve();
        });
    });
};

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * управление удаленными источниками.
 * 
 * Выполняет обновление информации об источнике в базе данных модуля. 
 * 
 * @param {*} sourceList - список источников
 */
module.exports.sourceManagementsUpdate = function(sourceList) {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let list = sourceList.map((item) => {
                let sourceID = +(item.source_id);
                let architecture = (item.source_settings.type_architecture_client_server === "server") ? true : false;
                let telemetry = (item.source_settings.transmission_telemetry === "on");

                sources.push(sourceID);

                return {
                    id: sourceID,
                    at: "update",
                    arg: {
                        ip: item.network_settings.ipaddress,
                        t: item.network_settings.token_id,
                        sn: item.short_name,
                        d: item.description,
                        s: {
                            as: architecture,
                            p: +(item.network_settings.port),
                            et: telemetry,
                            mcpf: +(item.source_settings.maximum_number_simultaneous_filtering_processes),
                            sf: item.source_settings.list_directories_with_file_network_traffic,
                            tan: item.source_settings.type_channel_layer_protocol,
                        },
                    }
                };
            });

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");

            if (conn !== null) {
                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: helpersFunc.getRandomHex(),
                    options: { sl: list },
                });
            }

            resolve();
        });
    });
};

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * управление удаленными источниками.
 * 
 * Выполняет удаление источников из базы данных модуля. 
 * 
 * @param {*} sourceList - список источников
 */
module.exports.sourceManagementsDel = function(sourceList) {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let list = sourceList.map((item) => {
                let sourceID = +(item.source);
                sources.push(sourceID);

                return {
                    id: sourceID,
                    at: "delete",
                    arg: {},
                };
            });

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");

            if (conn !== null) {
                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: helpersFunc.getRandomHex(),
                    options: { sl: list },
                });
            }

            resolve();
        });
    });
};

/** 
 * Обработчик для мо дуля сетевого взаимодействия осуществляющий
 * управление удаленными источниками.
 *  
 * Выполняет удаление источников из базы данных модуля. 
 *  
 * @param {*} sourceList - список источников
 */
module.exports.sourceManagementsReconnect = function(sourceList) {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let sourceNotFound = [];
            let sourceNotConnection = [];

            sourceList.forEach((source) => {
                let sourceInfo = globalObject.getData("sources", source);
                if (sourceInfo === null) {
                    sourceNotFound.push(source);
                } else if (!sourceInfo.connectStatus) {
                    sourceNotConnection.push(source);
                } else {
                    sources.push({
                        id: source,
                        at: "reconnect",
                        arg: {},
                    });
                }
            });

            if (sourceNotFound.length > 0) {
                let textOne = (sourceNotFound.length > 1) ? "Источники" : "Источник";
                let textTwo = (sourceNotFound.length > 1) ? "найдены" : "найден";

                return reject(new MyError("management network interaction", `${textOne} с идентификатором ${sourceNotFound.join(",")} не ${textTwo}.`));
            }

            if (sourceNotConnection.length > 0) {
                let textOne = (sourceNotConnection.length > 1) ? "Источники" : "Источник";
                let textTwo = (sourceNotConnection.length > 1) ? "подключены" : "подключен";

                return reject(new MyError("management network interaction", `${textOne} с идентификатором ${sourceNotConnection.join(",")} не ${textTwo}.`));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");

            if (conn !== null) {
                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: helpersFunc.getRandomHex(),
                    options: { sl: sources },
                });
            }

            resolve();
        });
    });
};


/**
 * Запрос на получение нового списка источников
 */
module.exports.giveNewShortSourceList = function() {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            if (conn !== null) {
                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "get an updated list of sources",
                    taskID: helpersFunc.getRandomHex(),
                    options: {}
                });
            }

            resolve();
        });
    });
};

/** ---  УПРАВЛЕНИЕ ЗАДАЧАМИ ПО ФИЛЬТРАЦИИ СЕТЕВОГО ТРАФИКА --- **/

/**  
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * управление задачами по фильтрации сетевого трафика.
 *   
 * Осуществляет запуск задачи по фильтрации сет. трафика. 
 *  
 * @param {*} filteringParameters - параметры фильтрации
 * @param {*} userLogin - логин пользователя
 * @param {*} userName - имя пользователя
 */
module.exports.managementTaskFilteringStart = function(filteringParameters, userLogin, userName) {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            //проверяем существование источника и статус его соединения
            let sourceInfo = globalObject.getData("sources", filteringParameters.source);
            if (sourceInfo === null) {
                return reject(new MyError("management network interaction", `Источник с идентификатором ${filteringParameters.source} не найден.`));

            }
            if (!sourceInfo.connectStatus) {
                return reject(new MyError("management network interaction", `Источник с идентификатором ${filteringParameters.source} не подключен.`));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            if (conn !== null) {
                let tmp = {
                    msgType: "command",
                    msgSection: "filtration control",
                    msgInstruction: "to start filtering",
                    taskID: helpersFunc.getRandomHex(),
                    options: {
                        id: filteringParameters.source,
                        un: userName,
                        dt: {
                            s: filteringParameters.dateTime.start,
                            e: filteringParameters.dateTime.end,
                        },
                        p: filteringParameters.networkProtocol,
                        f: filteringParameters.inputValue,
                    },
                };

                conn.sendMessage(tmp);
            }

            resolve();
        });
    });
};

/** 
 * Обработчи к для модуля сетевого взаимодействия осуществляющий
 * управление задачами по фильтрации сетевого трафика.
 *   
 * Осуществляет останов задачи по фильтрации сет. трафика. 
 * 
 * @param {*} taskID - ID останавливаемой задачи
 * @param {*} sourceID - ID источника
 */
module.exports.managementTaskFilteringStop = function(taskID, sourceID) {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            //проверяем существование источника и статус его соединения
            let sourceInfo = globalObject.getData("sources", sourceID);
            if (sourceInfo === null) {
                return reject(new MyError("management network interaction", `Источник с идентификатором ${sourceID} не найден.`));

            }
            if (!sourceInfo.connectStatus) {
                return reject(new MyError("management network interaction", `Источник с идентификатором ${sourceID} не подключен.`));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            if (conn !== null) {
                conn.sendMessage({
                    msgType: "command",
                    msgSection: "filtration control",
                    msgInstruction: "to cancel filtering",
                    taskID: taskID,
                    options: {},
                });
            }

            resolve();
        });
    });
};

/** ---  УПРАВЛЕНИЕ ЗАПРОСАМИ ДЛЯ ПОЛУЧЕНИЯ ИНФОРМАЦИИ О ЗАДАЧАХ --- **/

/**    
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * запрос всей информации о задаче по ее ID.
 * 
 * @param {*} socketIo   
 * @param {*} taskID - ID задачи по которой нужно найти информацию
 */
module.exports.managementRequestShowTaskAllInfo = function(socketIo, taskID) {
    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        if (conn !== null) {
            let hex = helpersFunc.getRandomHex();

            globalObject.setData("tasks", hex, {
                eventName: "show all information about task",
                eventForWidgets: false,
                userSessionID: sessionId,
                generationTime: +new Date(),
                socketId: socketIo.id,
            });

            conn.sendMessage({
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "get all information by task ID",
                taskID: hex,
                options: { rtid: taskID }
            });
        }
    });
};

/**   
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * запрос всего списка задач 
 * 
 * @param {*} socketIo 
 */
module.exports.managementRequestGetListAllTasks = function(socketIo) {
    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {

        debug("func 'managementRequestGetListAllTasks'");
        debug(`found user session id: ${sessionId}`);

        if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        if (conn !== null) {
            let hex = helpersFunc.getRandomHex();

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "list all tasks",
                eventForWidgets: false,
                userSessionID: sessionId,
                generationTime: +new Date(),
                socketId: socketIo.id,
            });

            debug(`Get list all tasks, TaskID: ${hex}`);

            conn.sendMessage({
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: {
                    sriga: true, //отмечаем что задача выполняется в автоматическом режиме 
                },
            });
        }
    });
};

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * запрос списка задач по которым не были выгружены все файлы.
 *  
 * @param {*} socketIo 
 * @param {*} data
 */
module.exports.managementRequestGetListTasksDownloadFiles = function(socketIo, data) {
    let forWidgets = true;
    let hex = helpersFunc.getRandomHex();

    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        if (conn !== null) {
            if ((typeof data.arguments === "undefined") || (typeof data.arguments.forWidgets === "undefined")) {
                forWidgets = false;
            } else {
                forWidgets = data.arguments.forWidgets;
            }

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "list tasks which need to download files",
                eventForWidgets: forWidgets,
                userSessionID: sessionId,
                generationTime: +new Date(),
                socketId: socketIo.id,
            });

            debug(`Get list downloaded files tasks, TaskID: ${hex}, forWidgets: '${forWidgets}'`);

            conn.sendMessage({
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: {
                    sriga: true, //отмечаем что задача выполняется в автоматическом режиме
                    jcn: forWidgets,
                    sft: "complete",
                    cpafid: true,
                    afid: false,
                    iaf: {
                        fif: true,
                    }
                },
            });
        }
    });
};

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * запрос списка задач, не отмеченных пользователем как завершенные
 * 
 * @param {*} socketIo 
 * @param {*} data
 */
module.exports.managementRequestGetListUnresolvedTasks = function(socketIo, data) {
    let forWidgets = true;
    let hex = helpersFunc.getRandomHex();

    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {

        console.log(`session ID: ${sessionId}, func 'managementRequestGetListUnresolvedTasks'`);

        if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        if (conn !== null) {
            if ((typeof data.arguments === "undefined") || (typeof data.arguments.forWidgets === "undefined")) {
                forWidgets = false;
            } else {
                forWidgets = data.arguments.forWidgets;
            }

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "list unresolved tasks",
                eventForWidgets: forWidgets,
                userSessionID: sessionId,
                generationTime: +new Date(),
                socketId: socketIo.id,
            });

            debug(`Get list unresolved tasks, TaskID: ${hex}`);

            conn.sendMessage({
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: {
                    sriga: true, //отмечаем что задача выполняется в автоматическом режиме
                    jcn: forWidgets,
                    sft: "complete",
                    cptp: true,
                    tp: false,
                    cpfid: true,
                    fid: true,
                    iaf: {
                        fif: true,
                    }
                },
            });
        }
    });
};

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * запрос списка задач по заданным критериям поиска
 * 
 * @param {*} socketIo 
 * @param {*} data 
 */
module.exports.managementRequestSearchInformationAboutTasks = function(socketIo, data) {
    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        if (conn !== null) {
            let hex = helpersFunc.getRandomHex();

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "list all tasks",
                eventForWidgets: false,
                userSessionID: sessionId,
                generationTime: +new Date(),
                socketId: socketIo.id,
            });

            data.sriga = true;

            //если начальная дата больше или равна конечной
            if (data.ifo.dt.s >= data.ifo.dt.e) {
                data.ifo.dt.s = 0;
                data.ifo.dt.e = 0;
            }

            conn.sendMessage({
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: data,
            });
        }
    });
};

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * запрос на удаление информации о задачах
 * 
 * @param {*} listTaskID 
 */
module.exports.managementRequestDeleteInformationAboutTask = function(listTaskID) {
    return new Promise((resolve, reject) => {
        if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        if (conn !== null) {
            conn.sendMessage({
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "delete all information about a task",
                taskID: helpersFunc.getRandomHex(),
                options: { ltid: listTaskID },
            });

            resolve();
        }
    });
};

/**
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * запрос всей аналитической информации о задаче по ее ID.
 * 
 * @param {*} socketIo 
 * @param {*} taskID - ID задачи по которой нужно найти информацию
 */
module.exports.managementRequestShowAnalyticsInformationAboutTaskID = function(socketIo, taskID) {
    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        if (conn !== null) {
            let hex = helpersFunc.getRandomHex();

            globalObject.setData("tasks", hex, {
                eventName: "common analytics information about task ID",
                eventForWidgets: false,
                userSessionID: sessionId,
                generationTime: +new Date(),
                socketId: socketIo.id,
            });

            conn.sendMessage({
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "get common analytics information about task ID",
                taskID: hex,
                options: { rtid: taskID }
            });
        }
    });
};

/**
 * Запрос на изменение статуса задачи на 'завершена'
 * 
 * @param {*} data 
 */
module.exports.managementRequestMarkTaskCompleted = function({ taskID = null, userName = "", description = "" }) {
    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (taskID === null) {
                reject(new Error("invalid task ID"));
            }

            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            if (conn !== null) {
                conn.sendMessage({
                    msgType: "command",
                    msgSection: "information search control",
                    msgInstruction: "mark an task as completed",
                    taskID: helpersFunc.getRandomHex(),
                    options: {
                        rtid: taskID,
                        un: userName,
                        d: description,
                    }
                });
            }

            resolve();
        });
    });
};

/** ---  УПРАВЛЕНИЕ ЗАДАЧАМИ СВЯЗАННЫМИ С ПОЛУЧЕНИЕМ ТЕЛЕМЕТРИИ ИСТОЧНИКОВ --- **/

/**  
 * Обработчик для модуля сетевого взаимодействия осуществляющий
 * управление задачами по получению телеметрии с источников.
 *   
 * Осуществляет запрос телеметрии с источника или группы источников. 
 *  
 * @param {*} sourceList - список источников
 */
module.exports.managementTaskGetTelemetry = function(sourceList) {

    console.log("func 'managementTaskGetTelemetry'");
    console.log(sourceList);

    return new Promise((resolve, reject) => {
        process.nextTick(() => {
            if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            if (conn !== null) {
                let tmp = {
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "give information about state of source",
                    taskID: helpersFunc.getRandomHex(),
                    options: {
                        lsid: sourceList,
                        ga: false,
                    },
                };

                conn.sendMessage(tmp);
            }

            resolve();
        });
    });
};