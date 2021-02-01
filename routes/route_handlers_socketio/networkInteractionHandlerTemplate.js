"use strict";

const async = require("async");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const createUniqID = require("../../libs/helpers/createUniqID");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

/**
 * Модуль обработчик запросов связанных с получения информации о
 * параметрах и состоянии источников (телеметрии)
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo, eventEmiterTimerTick) {
    const handlers = {
        "network interaction: create new template": createNewTemplate,
        "network interaction: get all list template": getAllListTemplate,
        "network interaction: delete template": deleteTemplate,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo, eventEmiterTimerTick));
    }
};

function createNewTemplate(socketIo, eventEmiterTimerTick, data) {
    let funcName = " (func 'createNewTemplate')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            if (typeof data.arguments === "undefined") {
                throw new MyError("management validation", "Приняты некорректные параметры запроса.");
            }

            return authData.document.userName;
        }).then((userName) => {
            //проверяем параметры полученные от пользователя
            if (!checkTemplateParameters(data.arguments)) {
                throw new MyError("management validation", "Приняты некорректные параметры запроса.");
            }

            return userName;
        }).then((userName) => {
            //получаем уникальный ID задачи
            let taskID = getTaskID(data.arguments);

            return new Promise((resolve) => {
                eventEmiterTimerTick.once("response get new temp task", (taskData) => {
                    resolve({
                        templateIsExist: (taskData !== null),
                        taskID: taskID,
                        userName: userName,
                    });
                });

                eventEmiterTimerTick.emit("get new temp task", { taskID: taskID });
            });
        }).then((result) => {
            if (result.templateIsExist) {
                return showNotify({
                    socketIo: socketIo,
                    type: "info",
                    message: "Шаблон с заданными параметрами уже существует."
                });
            }

            async.parallel([
                (callback) => {
                    //добавляем задачу в TempTaskStorage
                    eventEmiterTimerTick.once("response set new temp task", () => {
                        callback(null);
                    });

                    data.arguments.userName = result.userName;
                    data.arguments.timeCreation = +new Date;

                    eventEmiterTimerTick.emit("set new temp task", { taskID: result.taskID, parameters: data.arguments });
                },
                (callback) => {

                    console.log("func 'createNewTemplate'");
                    console.log(data.arguments);

                    let doc = {
                        template_id: result.taskID,
                        user_name: result.userName,
                        time_creation: +new Date,
                        date_time_trigger: {
                            weekday: data.arguments.timeSettings.listSelectedDays,
                            hour: data.arguments.timeSettings.timeTrigger.hour,
                            minutes: data.arguments.timeSettings.timeTrigger.minutes,
                        },
                        type: data.arguments.type,
                        list_source_id: data.arguments.listSources,
                    };

                    if (data.arguments.type === "filtration") {
                        doc.task_parameters = {
                            filtration: {
                                network_protocol: data.arguments.parametersFiltration.networkProtocol,
                                start_date: data.arguments.parametersFiltration.startDate,
                                end_date: data.arguments.parametersFiltration.endDate,
                                input_value: {
                                    ip: data.arguments.parametersFiltration.inputValue.ip,
                                    pt: data.arguments.parametersFiltration.inputValue.pt,
                                    nw: data.arguments.parametersFiltration.inputValue.nw,
                                }
                            }
                        };
                    }

                    //добавляем задачу в БД
                    mongodbQueryProcessor.queryCreate(models.modelTemplateAction, {
                        document: doc
                    }, (err) => {
                        if (err) {
                            return callback(err);
                        }

                        callback(null);
                    });
                }
            ], (err) => {
                if (err) {
                    throw err;
                }
            });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else if (err.name === "management validation") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: `Задача по формированию шаблона типовых действий, отклонена. ${err.message}`,
                });
            } else {
                let msg = "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.";

                if ((err.message.toString()).includes("duplicate key")) {
                    msg = "Совпадение ключевых полей, запись в базу данных невозможен.";
                }

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });
            }

            writeLogFile("error", err.toString() + funcName);
        }).finally(() => {
            //отправляем в UI сообщение, для того чтобы, выполнить автоматическое обновление страницы
            eventEmiterTimerTick.once("response get all new temp task", (data) => {
                socketIo.emit("network interaction: response list new template", { arguments: data });
            });

            eventEmiterTimerTick.emit("get all new temp task", {});
        });
}

function getAllListTemplate(socketIo, eventEmiterTimerTick, data) {
    let funcName = " (func 'getAllListTemplate')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            eventEmiterTimerTick.once("response get all new temp task", (data) => {
                socketIo.emit("network interaction: response list new template", { arguments: data });
            });

            eventEmiterTimerTick.emit("get all new temp task", {});
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
                });
            }

            writeLogFile("error", err.toString() + funcName);
        });
}

function deleteTemplate(socketIo, eventEmiterTimerTick, data) {
    let funcName = " (func 'deleteTemplate')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return;
        }).then(() => {
            async.parallel([
                (callback) => {
                    eventEmiterTimerTick.once("response del new temp task", () => {
                        callback(null);
                    });

                    eventEmiterTimerTick.emit("del new temp task", { taskID: data.arguments.templateID });
                },
                (callback) => {
                    //удаляем задачу из БД
                    mongodbQueryProcessor.queryDelete(models.modelTemplateAction, {
                        query: { template_id: data.arguments.templateID }
                    }, (err) => {
                        if (err) {
                            return callback(err);
                        }

                        callback(null);
                    });
                }
            ], (err) => {
                if (err) {
                    throw err;
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

                if ((err.message.toString()).includes("duplicate key")) {
                    msg = "Совпадение ключевых полей, запись в базу данных невозможен.";
                }

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });

                writeLogFile("error", err.toString() + funcName);
            }
        }).finally(() => {
            socketIo.emit("network interaction: response del new temp task", { arguments: { templateID: data.arguments.templateID } });
        });
}

function checkTemplateParameters(templateParameters) {
    //проверяем тип шаблона
    if (!((templateParameters.type === "telemetry") || (templateParameters.type === "filtration"))) {
        return false;
    }

    //проверяем список источников
    if (templateParameters.listSources.length !== 0) {
        for (let i = 0; i < templateParameters.listSources.length; i++) {
            //проверяем наличие id источника
            if (!helpersFunc.checkInputValidation({ name: "hostID", value: +templateParameters.listSources[i] })) {
                return false;
            }
        }
    }

    const hour = +templateParameters.timeSettings.timeTrigger.hour;
    const minutes = +templateParameters.timeSettings.timeTrigger.minutes;

    //проверяем время
    if ((isNaN(hour)) || !(hour >= 0 || hour <= 12)) {
        return false;
    }

    if ((isNaN(minutes)) || !(hour >= 0 || hour <= 60)) {
        return false;
    }

    //проверяем список выбранных дней недели
    if ((Object.keys(templateParameters.timeSettings.listSelectedDays)).length === 0) {
        return false;
    }

    const daysShort = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const daysName = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"];

    for (let day in templateParameters.timeSettings.listSelectedDays) {
        if ((!daysShort.includes(day)) || (!daysName.includes(templateParameters.timeSettings.listSelectedDays[day]))) {
            return false;
        }
    }

    console.log("func 'checkTemplateParameters', START...");
    console.log(templateParameters);

    if (templateParameters.type === "telemetry") {
        return true;
    }

    //проверяем время
    if (!helpersFunc.checkInputValidation({ name: "intervalTransmission", value: templateParameters.parametersFiltration.startDate })) {

        console.log("func 'checkTemplateParameters', ERROR time start");

        return false;
    }
    if (!helpersFunc.checkInputValidation({ name: "intervalTransmission", value: templateParameters.parametersFiltration.endDate })) {

        console.log("func 'checkTemplateParameters', ERROR time end");

        return false;
    }
    if (+templateParameters.parametersFiltration.startDate > +templateParameters.parametersFiltration.endDate) {

        console.log("func 'checkTemplateParameters', ERROR time start and end");
        console.log(`+templateParameters.parametersFiltration.startDate (${+templateParameters.parametersFiltration.startDate}) > (${+templateParameters.parametersFiltration.endDate}) +templateParameters.parametersFiltration.endDate`);

        return false;
    }

    let checkNetworkPortIP = (section, type) => {
        let validInput = {
            any: [],
            src: [],
            dst: [],
        };

        for (let d in templateParameters.parametersFiltration.inputValue[section]) {
            validInput[d] = templateParameters.parametersFiltration.inputValue[section][d].filter((item) => {
                return helpersFunc.checkInputValidation({
                    name: type,
                    value: item,
                });
            });
        }

        return validInput;
    };

    let newInputValue = {
        ip: checkNetworkPortIP("ip", "ipaddress"),
        nw: checkNetworkPortIP("nw", "network"),
        pt: checkNetworkPortIP("pt", "port"),
    };

    let checkExistInputValue = (inputValue) => {
        let isEmpty = true;

        done:
            for (let et in inputValue) {
                for (let d in inputValue[et]) {
                    if (Array.isArray(inputValue[et][d]) && inputValue[et][d].length > 0) {
                        isEmpty = false;

                        break done;
                    }
                }
            }

        return isEmpty;
    };

    //проверяем наличие хотя бы одного параметра в inputValue
    if (checkExistInputValue(newInputValue)) {

        console.log("func 'checkTemplateParameters', ERROR input value");

        return false;
    }

    console.log("======================");

    return true;
}

function getTaskID(templateParameters) {
    let stringParameters = templateParameters.type + templateParameters.listSources.join();
    stringParameters += templateParameters.timeSettings.timeTrigger.hour;
    stringParameters += templateParameters.timeSettings.timeTrigger.minutes;
    stringParameters += Object.keys(templateParameters.timeSettings.listSelectedDays).join();

    return createUniqID.getMD5(stringParameters);
}