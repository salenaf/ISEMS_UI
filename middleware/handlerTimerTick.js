"use strick";

const EventEmitter = require("events");

class MyEmitter extends EventEmitter {}

class TempTaskStorage {
    constructor() {
        /**
         * this.obj = {
         *   "telemetry": {
         *     "taskID": {
         *       dateTimeTrigger: [""],
         *       sourcesID: []
         *     }
         *   },
         */

        /* 
        const globalObject = require("../configure/globalObject");
            let socketIo = globalObject.getData("descriptionSocketIo", "userConnections", userSocketId);

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
 */

        /**
         * {
         *     "listDateTimeTrigger": [
         *         {  
         *             dateTimeTrigger: {
         *                 weekday: [] //дни недели, перечисляются сокращенно (если пусто значит каждый день)
         *                 hour: <час>,
         *                 minutes: <минута>,           
         *             },
         *             taskType: "telemetry", //тип задачи ("telemetry", "filtration")
         *             taskParameters: { //параметры задачи, зависит от типа
         *                 listSourceID: [], //список источников для которых применима задача, если пусто то для всех
         *             }
         *         },
         *     ],
         * }
         */
        this.obj = {
            "listDateTimeTrigger": [],
        };
    }

    /**
     * 
     * @param {*} myEmitter 
     * @param {*} data { tempType: "", options: { dateTimeTrigger: {}, taskParameters: {} } }
     */
    setTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'setTempTask'");
        console.log(data);

        /*
1. получаем параметры и выполняем валидацию
2. проверяем наличие подобной задачи. Для "telemetry" попроще, если полное соответствие то
 отклоняем задачу с вердиктом "подобная задача уже существует". Для "filtration" следует
 учитывать частоту задач по фильтрации, они не должны быть сличком часто заданны,
 так как может неуспеть закончится предидущая фильтрация как начнется следующая
3. добавляем вновь сформированные задачи в "listDateTimeTrigger"
 */

    }

    getTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'getTempTask'");
        console.log(data);

        /** 
         * надо вернуть информацию о задаче по ее типу и идентификатору 
         * */
    }

    getAllTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'getAllTempTask'");
        console.log(data);

        /** 
         * надо вернуть информацию о всех задачах по определенному типу 
         * */
    }

    delTempTask(myEmitter, data) {
        console.log("class 'TempTaskStorage', func 'delTempTask'");
        console.log(data);
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

    myEmitter.on("set new temp task", (myEmitter, data) => {
        console.log("func 'handlerTimerTick', received event 'set new temp task'");

        tempTaskStorage.setTempTask(myEmitter, data);
    });

    myEmitter.on("get new temp task", (myEmitter, data) => {
        console.log("func 'handlerTimerTick', received event 'get new temp task'");

        tempTaskStorage.getTempTask(myEmitter, data);
    });

    myEmitter.on("get all new temp task", (myEmitter, data) => {
        console.log("func 'handlerTimerTick', received event 'get all new temp task'");

        tempTaskStorage.getAllTempTask(myEmitter, data);
    });

    myEmitter.on("del new temp task", (myEmitter, data) => {
        console.log("func 'handlerTimerTick', received event 'del new temp task'");

        tempTaskStorage.delTempTask(myEmitter, data);
    });

    return myEmitter;
};