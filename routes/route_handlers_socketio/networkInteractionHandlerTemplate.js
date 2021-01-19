"use strict";

const debug = require("debug")("niht");

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
    debug("func 'createNewTemplate', START...");
    debug(data);

    let funcName = "createNewTemplate";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            if (typeof data.arguments === "undefined") {
                throw new MyError("management validation", "Приняты некорректные параметры запроса.");
            }

            return;
        }).then(() => {
            //проверяем параметры полученные от пользователя
            debug("func 'createNewTemplate', проверяем параметры полученные от пользователя");

            if (!checkTemplateParameters(data.arguments)) {
                throw new MyError("management validation", "Приняты некорректные параметры запроса.");
            }

            return;
        }).then(() => {
            //получаем уникальный ID задачи
            debug("func 'createNewTemplate', получаем никальный ID задачи");

            let taskID = getTaskID(data.arguments);

            debug(`func 'createNewTemplate', ID задачи: ${taskID}`);

            //проверяем наличие задачи с такиме же параметрами
            debug("func 'createNewTemplate', проверяем наличие задачи с такиме же параметрами");

            return new Promise((resolve, reject) => {
                eventEmiterTimerTick.on("response get new temp task", (taskData) => {
                    resolve({ templateIsExist: (taskData !== null), taskID: taskID });
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

            //добавляем задачу в БД и в объект TempTaskStorage
            debug("func 'createNewTemplate', добавляем задачу в БД и в объект TempTaskStorage");

            async.parallel([
                (callback) => {
                    //добавляем задачу в TempTaskStorage
                    eventEmiterTimerTick.on("response set new temp task", () => {
                        callback(null);
                    });

                    eventEmiterTimerTick.emit("set new temp task", { taskID: result.taskID, parameters: data.arguments });
                },
                (callback) => {
                    //добавляем задачу в БД
                    mongodbQueryProcessor.queryCreate(models.modelTemplateAction, {
                        document: {
                            template_id: result.taskID,
                            date_time_trigger: {
                                weekday: data.arguments.timeSettings.listSelectedDays,
                                hour: data.arguments.timeSettings.timeTrigger.hour,
                                minutes: data.arguments.timeSettings.timeTrigger.minutes,
                            },
                            type: data.arguments.type,
                            list_source_id: data.arguments.listSources,
                            task_parameters: {},
                        }
                    }, (err) => {
                        if (err) {
                            return callback(err);
                        }

                        callback(null);
                    });
                }
            ], (err) => {
                debug("func 'createNewTemplate', send message 'OK' to UI");

                /**
                 * событие "response get all new temp task" похоже не происходит
                 * хотя надо проверить
                 * 
                 */

                //отправляем в UI сообщение, для того чтобы, выполнить автоматическое обновление страницы
                eventEmiterTimerTick.on("response get all new temp task", (data) => {
                    socketIo.emit("network interaction: response list new template", { arguments: data });
                });

                eventEmiterTimerTick.emit("get all new temp task", {});

                if (err) {
                    //только для БД (пишем в лог)
                    debug(`func 'createNewTemplate', ERROR: ${err.toString()}`);

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
            } else if (err.name === "management network interaction") {
                //при отсутствии доступа к модулю сетевого взаимодействия
                showNotify({
                    socketIo: socketIo,
                    type: "warning",
                    message: err.message.toString()
                });
            } else {

                debug(err);

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
        });
}

function getAllListTemplate(socketIo, eventEmiterTimerTick, data) {
    debug("func 'getAllListTemplate', START...");
    debug(data);
}

function deleteTemplate(socketIo, eventEmiterTimerTick, data) {
    debug("func 'deleteTemplate', START...");
    debug(data);
}

function checkTemplateParameters(templateParameters) {
    debug("func 'checkTemplateParameters', START");

    debug("func 'checkTemplateParameters', test template");
    //проверяем тип шаблона
    if (!((templateParameters.type === "telemetry") || (templateParameters.type === "filtration"))) {
        return false;
    }

    debug("func 'checkTemplateParameters', test source list");
    //проверяем список источников
    if (templateParameters.listSources.length !== 0) {
        for (let i = 0; i < templateParameters.listSources.length; i++) {

            debug(`func 'checkTemplateParameters', source id: ${+templateParameters.listSources[i]}`);
            debug(`func 'checkTemplateParameters', result: ${(!helpersFunc.checkInputValidation({ name: "hostID", value: +templateParameters.listSources[i] }))}`);

            //проверяем наличие id источника
            if (!helpersFunc.checkInputValidation({ name: "hostID", value: +templateParameters.listSources[i] })) {
                return false;
            }
        }
    }

    const hour = +templateParameters.timeSettings.timeTrigger.hour;
    const minutes = +templateParameters.timeSettings.timeTrigger.minutes;

    debug("func 'checkTemplateParameters', test time hour");
    //проверяем время
    if ((isNaN(hour)) || !(hour >= 0 || hour <= 12)) {
        return false;
    }

    debug("func 'checkTemplateParameters', test time minutes");
    if ((isNaN(minutes)) || !(hour >= 0 || hour <= 60)) {
        return false;
    }

    debug("func 'checkTemplateParameters', test list days of week");
    //проверяем список выбранных дней недели
    if ((Object.keys(templateParameters.timeSettings.listSelectedDays)).length === 0) {

        debug("func 'checkTemplateParameters', test list days of week FALSE");

        return false;
    }

    const daysShort = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const daysName = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"];

    for (let day in templateParameters.timeSettings.listSelectedDays) {

        debug(`func 'checkTemplateParameters', (!daysShort.includes(day): ${(!daysShort.includes(day))}`);
        debug(`func 'checkTemplateParameters', (!daysName.includes(templateParameters.timeSettings.listSelectedDays[day]): ${(!daysName.includes(templateParameters.timeSettings.listSelectedDays[day]))}`);

        if ((!daysShort.includes(day)) || (!daysName.includes(templateParameters.timeSettings.listSelectedDays[day]))) {
            return false;
        }
    }

    debug("func 'checkTemplateParameters', all test is OK");

    //проверяем параметры фильтрации
    //let obj = (require("../../libs/processing/route_socketio/validationFileFilteringParameters"))(data.arguments);

    return true;
}

function getTaskID(templateParameters) {
    let stringParameters = templateParameters.type + templateParameters.listSources.join();
    stringParameters += templateParameters.timeSettings.timeTrigger.hour;
    stringParameters += templateParameters.timeSettings.timeTrigger.minutes;
    stringParameters += Object.keys(templateParameters.timeSettings.listSelectedDays).join();

    debug(`func 'getTaskID', stringParameters: ${stringParameters}`);

    return createUniqID.getMD5(stringParameters);
}