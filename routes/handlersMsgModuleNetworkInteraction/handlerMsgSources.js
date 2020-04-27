"use strict";

const debug = require("debug")("handlerMsgSources");

const showNotify = require("../../libs/showNotify");
const globalObject = require("../../configure/globalObject");

/**
 * Обработчик информационных сообщений получаемых от
 * модуля сетевого взаимодействия на действия с источниками
 * 
 * @param {*} msg - сообщение от модуля сетевого взаимодействия
 */
module.exports = function(msg, socketIo){
    let task = globalObject.getData("tasks", "networkInteractionTaskList", msg.taskID);    

    if(task === null) return;

    //    let isAddSource = task.instructionTask === "add source list";
    let isSourceControl = task.sectionTask === "source control";

    if(isSourceControl /*&& isAddSource*/ && msg.options.ti.s === "end"){
        msg.options.sl.forEach((item) => {

            debug(item);

            showNotify({
                socketIo: socketIo,
                type: (item.is) ? "success" : "warning",
                message: item.mf,
            });
        });
       
        globalObject.deleteData("tasks", "networkInteractionTaskList", msg.taskID);
    }

    /**
     * Добавление источника в модуль сетевого взаимодействия я сделал
     * теперь, удаление, обновление и реконнект.
     * Кроме того нужно сделать в globalObject объект со списком источников
     * и учет статуса их соединения 
     */
};
