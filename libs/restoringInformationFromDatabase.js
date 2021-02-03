"use strict";

const models = require("../controllers/models");
const mongodbQueryProcessor = require("../middleware/mongodbQueryProcessor");

/**
 * Модуль восстанавливает информацию из БД
 * 
 * @param {*} eventEmiterTempTaskStorage - генератор событий для восстановления информаци в TempTaskStorage 
 */
module.exports = async function(eventEmiterTempTaskStorage) {
    await restoreTempTaskStorage(eventEmiterTempTaskStorage);
};

function restoreTempTaskStorage(eventEmiterTempTaskStorage) {
    return new Promise((resolve, reject) => {
        //получаем всю информацию из коллекции template_actions
        mongodbQueryProcessor.querySelect(models.modelTemplateAction, {
            isMany: true,
            select: { _id: 0 },
        }, (err, data) => {
            if (err) {
                reject(err);
            }

            resolve(data);
        });
    }).then((listTemplateActions) => {
        //восстанавливаем список шаблонов для хранилище TempTaskStorage
        listTemplateActions.forEach((element) => {

            console.log("func 'restoreTempTaskStorage'");
            console.log(element);

            eventEmiterTempTaskStorage.emit("set new temp task", {
                taskID: element.template_id,
                parameters: {
                    userName: element.user_name,
                    timeCreation: element.time_creation,
                    type: element.type,
                    listSources: element.list_source_id,
                    timeSettings: {
                        timeTrigger: {
                            hour: element.date_time_trigger.hour,
                            minutes: element.date_time_trigger.minutes,
                            full: element.date_time_trigger.full,
                        },
                        listSelectedDays: element.date_time_trigger.weekday,
                    },
                    parametersFiltration: {
                        networkProtocol: element.task_parameters.filtration.network_protocol,
                        minHour: element.task_parameters.filtration.min_hour,
                        maxHour: element.task_parameters.filtration.max_hour,
                        inputValue: element.task_parameters.filtration.input_value,
                    },
                },
            });
        });
    });
}