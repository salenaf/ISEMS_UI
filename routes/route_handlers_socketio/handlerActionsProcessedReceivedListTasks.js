"use strict";

const showNotify = require("../../libs/showNotify");
const writeLogFile = require("../../libs/writeLogFile");
const globalObject = require("../../configure/globalObject");

const MAX_CHUNK_SIZE = 10;

/**
 * Обработчик модуля сетевого взаимодействия осуществляющий обработку
 * принятого списка всех задач (при этом поиск по каким либо критериям не осуществлялся)
 * 
 * @param {*} socketIo - дескриптор socketIo соединения
 * @param {*} data - полученные, от модуля сетевого взаимодействия, данные
 * @param {*} sessionId - ID сессии
 */
module.exports.receivedListAllTasks = function(socketIo, data, sessionId) {
    let funcName = " (func 'receivedListAllTasks')";

    console.log(`func '${funcName}', paginationOptions`);
    console.log(data.options.p);
    console.log(globalObject.hasData("tmpModuleNetworkInteraction", sessionId, "resultFoundTasks"));

    let resultFoundTasks = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "resultFoundTasks");

    console.log(`func '${funcName}', resultFoundTasks.taskID: '${resultFoundTasks.taskID}' and data.taskID: '${data.taskID}'`);

    if ((typeof resultFoundTasks.taskID === "undefined") || (resultFoundTasks.taskID !== data.taskID)) {
        //если ID задачи не совпадают создаем новую запись
        globalObject.setData("tmpModuleNetworkInteraction", sessionId, "resultFoundTasks", {
            taskID: data.taskID,
            status: data.options.s,
            numFound: data.options.tntf,
            paginationOptions: {
                chunkSize: data.options.p.cs,
                chunkNumber: data.options.p.cn,
                chunkCurrentNumber: data.options.p.ccn
            },
            listTasksDownloadFiles: data.options.slft,
        });
    } else {
        resultFoundTasks.listTasksDownloadFiles.push(data.options.slft);
    }

    let numFullChunks = 1;
    if (data.options.tntf > MAX_CHUNK_SIZE) {
        numFullChunks = Math.ceil(data.options.tntf / MAX_CHUNK_SIZE);
    }

    //отправляем в UI если это первый сегмент
    if (data.options.p.ccn === 1) {
        socketIo.emit("module NI API", {
            "type": "send a list of found tasks",
            "taskID": data.taskID,
            "options": {
                p: {
                    cs: MAX_CHUNK_SIZE, //размер части
                    cn: numFullChunks, //всего частей
                    ccn: 1, //номер текущей части
                },
                tntf: data.options.tntf,
                slft: require("../../libs/helpers/helpersFunc").modifyListFoundTasks(data.options.slft.slice(0, MAX_CHUNK_SIZE)),
            }
        });
    }
};

/**
 * Обработчик модуля сетевого взаимодействия осуществляющий обработку
 * принятого списка задач файлы по которым не выгружались
 * 
 * @param {*} socketIo - дескриптор socketIo соединения
 * @param {*} data - полученные, от модуля сетевого взаимодействия, данные
 * @param {*} taskInfo - краткая информация о задаче
 * 
 * Так как список задач файлы по которым не выгружались может
 * быть СЕГМЕНТИРОВАН и приходить в несколько частей нужно его 
 * временно сложить в память, а потом вытаскивать по мере запроса.
 * 
 * Исключение составляет первая или единственная часть которая
 * автоматически отправляется в UI
 */
module.exports.receivedListTasksDownloadFiles = function(socketIo, data, taskInfo) {
    let funcName = " (func 'receivedListTasksDownloadFiles')";
    let sessionId = taskInfo.userSessionID;

    if (!globalObject.getData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles")) {
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
        });

        return writeLogFile("error", "the 'listTasksDownloadFiles' property was not found in 'globalObject'" + funcName);
    }

    let numFullChunks = 1;
    if (data.options.tntf > MAX_CHUNK_SIZE) {
        numFullChunks = Math.ceil(data.options.tntf / MAX_CHUNK_SIZE);
    }

    //если только для виджета
    if (taskInfo.eventForWidgets) {
        socketIo.emit("module NI API", {
            "type": "get list tasks files not downloaded for widget",
            "taskID": data.taskID,
            "options": {
                p: {
                    cs: MAX_CHUNK_SIZE, //размер части
                    cn: numFullChunks, //всего частей
                    ccn: 1, //номер текущей части
                },
                tntf: data.options.tntf,
            }
        });

        return;
    }

    let tasksDownloadFiles = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles");

    if ((typeof tasksDownloadFiles.taskID === "undefined") || (tasksDownloadFiles.taskID !== data.taskID)) {
        //если ID задачи не совпадают создаем новую запись
        globalObject.setData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles", {
            taskID: data.taskID,
            status: data.options.s,
            numFound: data.options.tntf,
            paginationOptions: {
                chunkSize: data.options.p.cs,
                chunkNumber: data.options.p.cn,
                chunkCurrentNumber: data.options.p.ccn
            },
            listTasksDownloadFiles: data.options.slft,
        });
    } else {
        tasksDownloadFiles.listTasksDownloadFiles.push(data.options.slft);
    }

    //отправляем в UI если это первый сегмент
    if (data.options.p.ccn === 1) {
        socketIo.emit("module NI API", {
            "type": "get list tasks files not downloaded",
            "taskID": data.taskID,
            "options": {
                p: {
                    cs: MAX_CHUNK_SIZE, //размер части
                    cn: numFullChunks, //всего частей
                    ccn: 1, //номер текущей части
                },
                tntf: data.options.tntf,
                slft: require("../../libs/helpers/helpersFunc").modifyListFoundTasks(data.options.slft.slice(0, MAX_CHUNK_SIZE)),
            }
        });
    }
};

/**
 * Обработчик модуля сетевого взаимодействия осуществляющий обработку
 * принятого списка задач, не отмеченых пользователем как завершенные
 * 
 * @param {*} socketIo - дескриптор socketIo соединения
 * @param {*} data - полученные, от модуля сетевого взаимодействия, данные
 * @param {*} taskInfo - краткая информация о задаче
 * 
 * Так как список задач, не отмеченых пользователем как завершенные, может
 * быть СЕГМЕНТИРОВАН и приходить в несколько частей нужно его 
 * временно сложить в память, а потом вытаскивать по мере запроса.
 * 
 * Исключение составляет первая или единственная часть которая
 * автоматически отправляется в UI
 */
module.exports.receivedListUnresolvedTask = function(socketIo, data, taskInfo) {
    let funcName = " (func 'receivedListUnresolvedTask')";
    let sessionId = taskInfo.userSessionID;

    if (!globalObject.getData("tmpModuleNetworkInteraction", sessionId, "unresolvedTask")) {
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
        });

        return writeLogFile("error", `the 'listUnresolvedTask' property for sessionId '${sessionId}' was not found in 'globalObject' ${funcName}`);
    }

    let numFullChunks = 1;
    if (data.options.tntf > MAX_CHUNK_SIZE) {
        numFullChunks = Math.ceil(data.options.tntf / MAX_CHUNK_SIZE);
    }

    //если только для виджета
    if (taskInfo.eventForWidgets) {
        socketIo.emit("module NI API", {
            "type": "get list unresolved task for widget",
            "taskID": data.taskID,
            "options": {
                p: {
                    cs: MAX_CHUNK_SIZE, //размер части
                    cn: numFullChunks, //всего частей
                    ccn: 1, //номер текущей части
                },
                tntf: data.options.tntf,
            }
        });

        return;
    }

    let unresolvedTask = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "unresolvedTask");

    if ((typeof unresolvedTask.taskID === "undefined") || (unresolvedTask.taskID !== data.taskID)) {
        //если ID задачи не совпадают создаем новую запись
        globalObject.setData("tmpModuleNetworkInteraction", sessionId, "unresolvedTask", {
            taskID: data.taskID,
            status: data.options.s,
            numFound: data.options.tntf,
            paginationOptions: {
                chunkSize: data.options.p.cs,
                chunkNumber: data.options.p.cn,
                chunkCurrentNumber: data.options.p.ccn
            },
            listUnresolvedTask: data.options.slft,
        });
    } else {
        unresolvedTask.listUnresolvedTask.push(data.options.slft);
    }

    //отправляем в UI если это первый сегмент
    if (data.options.p.ccn === 1) {
        socketIo.emit("module NI API", {
            "type": "get list unresolved task",
            "taskID": data.taskID,
            "options": {
                p: {
                    cs: MAX_CHUNK_SIZE, //размер части
                    cn: numFullChunks, //всего частей
                    ccn: 1, //номер текущей части
                },
                tntf: data.options.tntf,
                slft: require("../../libs/helpers/helpersFunc").modifyListFoundTasks(data.options.slft.slice(0, MAX_CHUNK_SIZE)),
            }
        });
    }
};