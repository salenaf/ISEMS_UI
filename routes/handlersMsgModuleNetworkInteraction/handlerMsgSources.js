"use strict";

const debug = require("debug")("handlerMsgSources");

const showNotify = require("../../libs/showNotify");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");

/**
 * Обработчик информационных сообщений получаемых от
 * модуля сетевого взаимодействия на действия с источниками
 * 
 * @param {*} msg - сообщение от модуля сетевого взаимодействия
 */
module.exports = function(msg, socketIo){
//    let task = globalObject.getData("tasks", "networkInteractionTaskList", msg.taskID);    
//    if(task === null) return;

    //    let isAddSource = task.instructionTask === "add source list";
    //    let isSourceControl = task.sectionTask === "source control";

    let task = globalObject.getData("tasks", "networkInteractionTaskList", msg.taskID);    
    if(task === null){
        debug(`instruction: ${msg.instruction}`);

        switch(msg.instruction){
        //получаем версию ПО ISEMS-NIH_slave
        case "send version app":
            require("../../libs/mongodb_requests/moduleNetworkInteraction/addVersionApp")(msg.options, (err) => {
                if(err){
                    writeLogFile("error", err.toString());
                }
            });

            break;

        //получаем состояние соединения с источником
        case "change status source":

            debug("case 'change status source'");

            globalObject.modifyData("sources", msg.options.id+"", [
                [ "connectStatus", (msg.options.s === "connect") ], 
                [ "connectTime", +(new Date) ]
            ]);

            let sourceInfo = globalObject.getData("sources", msg.options.id);
            
            /**
            * 
            * 
            * Не модифицируется объект
            * и не возвращается информация по источнику
            * 
            *   
            */

            debug(sourceInfo);

            if(sourceInfo !== null){
                debug("send message --->");

                socketIo.emit("module NI API", { 
                    "type": "change status source",
                    "options": {
                        sourceID: msg.options.id,
                        shortName: sourceInfo.shortName,
                        description: sourceInfo.description,
                        connectStatus: sourceInfo.connectStatus,
                        connectTime: sourceInfo.connectTime,
                        id: sourceInfo.id,
                    },
                });
            }

            break;
        }
        
        return;
    }

    if((task.sectionTask === "source control") && (msg.options.ti.s === "end")){
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
