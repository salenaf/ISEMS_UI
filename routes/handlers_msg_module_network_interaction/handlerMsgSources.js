"use strict";

const debug = require("debug")("handlerMsgSources");

const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");

/**
 * Обработчик информационных сообщений получаемых от
 * модуля сетевого взаимодействия на действия с источниками
 *
 * @param {*} msg - сообщение от модуля сетевого взаимодействия
 */
module.exports = function(msg, socketIo) {

    //ТОЛЬКО ДЛЯ ТЕСТА!!!
    if (Array.isArray(msg.options.sl)) {
        msg.options.sl.forEach((item) => {
            debug(`source ID: ${item.id}, connection status: ${item.cs}`);
            /*            if (item.id === 1000) {
                debug(item);
            }*/
        });
    }

    let objHandlerMsgInstraction = {
        "send version app": sendVersionApp,
        "change status source": changeStatusSource,
        "send current source list": sendCurrentSourceList,
    };

    const task = globalObject.getData("tasks", "networkInteractionTaskList", msg.taskID);
    if (task === null) {
        debug(`instruction: ${msg.instruction}`);

        if (objHandlerMsgInstraction[msg.instruction]) {
            objHandlerMsgInstraction[msg.instruction](msg, socketIo);
        }

        return;
    }

    if ((task.sectionTask === "source control") && (msg.options.ti.s === "end")) {
        msg.options.sl.forEach((item) => {
            debug(item);

            showNotify({
                socketIo: socketIo,
                type: (item.is) ? "success" : "warning",
                message: item.mf
            });
        });

        globalObject.deleteData("tasks", "networkInteractionTaskList", msg.taskID);
    }
};

function sendVersionApp(msg, socketIo) {
    require("../../libs/mongodb_requests/module_network_interaction/addVersionApp")(msg.options, (err) => {
        if (err) {
            writeLogFile("error", err.toString());
        }
    });
}

function changeStatusSource(msg, socketIo) {
    debug("Instraction: 'change status source'");

    if (!Array.isArray(msg.options.sl)) {
        return;
    }

    msg.options.sl.forEach((item) => {
        globalObject.modifyData("sources", item.id, [
            ["connectStatus", (item.s === "connect")],
            ["connectTime", +(new Date())]
        ]);

        const sourceInfo = globalObject.getData("sources", item.id);
        if (sourceInfo !== null) {

            debug("send message STATUS SOURCE --->");
            debug(`sourceID: '${item.id}', shortName: '${sourceInfo.shortName}', connectionStatus: '${sourceInfo.connectStatus}'`);

            socketIo.emit("module-ni:change status source", {
                options: {
                    sourceID: item.id,
                    shortName: sourceInfo.shortName,
                    description: sourceInfo.description,
                    connectStatus: sourceInfo.connectStatus,
                    connectTime: sourceInfo.connectTime,
                    id: sourceInfo.id
                }
            });

            // для виджетов
            socketIo.emit("module-ni:change sources connection", helpersFunc.getCountConnectionSources(globalObject));
        }
    });
}

function sendCurrentSourceList(msg, socketIo) {
    /**
     *
     * Здесь получаем список актуальных источников из базы
     * данных модуля сетевого взаимодействия.
     *
     * Пока из него только извлекаем состояния сетевого соединения
     * источников и записываем в глобальный объект
     *
     */

    if (!Array.isArray(msg.options.sl)) {
        return;
    }

    msg.options.sl.forEach((item) => {
        const modifyIsSuccess = globalObject.modifyData("sources", item.id, [
            ["connectStatus", item.cs],
            ["connectTime", item.dlc]
        ]);

        //debug(`source ID '${item.id}', modifyIsSuccess = ${modifyIsSuccess}`);

        // для источников которых нет в globalObject
        if (!modifyIsSuccess) {
            globalObject.setData("sources", item.id, {
                shortName: item.sn,
                description: item.d,
                connectStatus: item.cs,
                connectTime: item.dlc,
                id: ""
            });
        }
    });

    socketIo.emit("module-ni: short source list", {
        arguments: globalObject.getData("sources")
    });
}