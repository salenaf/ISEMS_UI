"use strick";

const EventEmitter = require("events");

class MyEmitter extends EventEmitter {}

class TempTaskStorage {
    constructor() {
        /**
         * {
         *     "listDateTimeTrigger": {}
         *         taskID: {  
         *             dateTimeTrigger: {
         *                 weekday: {} //дни недели, key = сокращенное название на английском, value = полное название на русском
         *                 hour: <час>,
         *                 minutes: <минута>,           
         *             },
         *             taskType: "telemetry", //тип задачи ("telemetry", "filtration")
         *             listSourceID: [], //список источников для которых применима задача, если пусто то для всех            
         *             taskParameters: {} //параметры задачи, пока только для фильтрации
         *         },
         *     },
         * }
         */
        this.obj = {
            "listDateTimeTrigger": {},
        };
    }

    /**
     * Добавляет новый шаблон
     * 
     * @param {*} myEmitter 
     * @param {*} data 
     */
    setTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'setTempTask'");
        console.log(data);

        if (typeof this.obj.listDateTimeTrigger[data.taskID] !== "undefined") {
            return;
        }

        this.obj.listDateTimeTrigger[data.taskID] = {
            dateTimeTrigger: {
                weekday: data.parameters.timeSettings.listSelectedDays,
                hour: data.parameters.timeSettings.timeTrigger.hour,
                minutes: data.parameters.timeSettings.timeTrigger.minutes,
            },
            taskType: "telemetry",
            listSourceID: data.parameters.listSources,
            taskParameters: {},
        };
    }

    /**
     * Возвращает шаблон по его ID
     * 
     * @param {*} myEmitter 
     * @param {*} data 
     */
    getTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'getTempTask'");
        console.log(data);
        console.log(`class 'TempTaskStorage', func 'getTempTask', task: '${this.obj.listDateTimeTrigger[data.taskID]}'`);

        let result = null;
        if (typeof this.obj.listDateTimeTrigger[data.taskID] !== "undefined") {
            result = this.obj.listDateTimeTrigger[data.taskID];
        }

        myEmitter.emit("response get new temp task", result);
    }

    /**
     * Возвращает список всех шаблонов
     * 
     * @param {*} myEmitter 
     * @param {*} data 
     */
    getAllTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'getAllTempTask'");
        console.log(data);

        myEmitter.emit("response get all new temp task", this.obj.listDateTimeTrigger);
    }

    /**
     * Удаляет выбранный шаблон по его ID
     * 
     * @param {*} myEmitter 
     * @param {*} data 
     */
    delTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'delTempTask'");
        console.log(data);

        delete this.obj.listDateTimeTrigger[data.taskID];
    }
}

/**
 * Обработчик таймера 
 */
module.exports = function(sec) {
    const myEmitter = new MyEmitter();
    let tempTaskStorage = new TempTaskStorage();

    setTimeout(() => {
        console.log(`Get timer: ${new Date}`);

        /**
         * здесь будет выполнятся регулярное чтение
         * объектов tempTaskStorage.telemetry и tempTaskStorage.filtration 
         */

    }, sec);

    myEmitter.on("set new temp task", (data) => {
        console.log("func 'handlerTimerTick', received event 'set new temp task'");
        console.log(data);

        tempTaskStorage.setTempTask(myEmitter, data);
    });

    myEmitter.on("get new temp task", (data) => {
        console.log("func 'handlerTimerTick', received event 'get new temp task'");
        console.log(data);

        tempTaskStorage.getTempTask(myEmitter, data);
    });

    myEmitter.on("get all new temp task", (data) => {
        console.log("func 'handlerTimerTick', received event 'get all new temp task'");
        console.log(data);

        tempTaskStorage.getAllTempTask(myEmitter, data);
    });

    myEmitter.on("del new temp task", (data) => {
        console.log("func 'handlerTimerTick', received event 'del new temp task'");
        console.log(data);

        tempTaskStorage.delTempTask(myEmitter, data);
    });

    return myEmitter;
};