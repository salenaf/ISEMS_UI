"use strict";

const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");

/**
 * Обработчик информационных сообщений получаемых от
 * модуля сетевого взаимодействия на действия с источниками
 *
 * @param {*} msg - сообщение от модуля сетевого взаимодействия
 */
module.exports = function(msg) {

    //console.log("func 'handlerMsgSources', START...");
    // console.log(msg);

    let objHandlerMsgInstraction = {
        "send version app": sendVersionApp,
        "change status source": changeStatusSource,
        "send current source list": sendCurrentSourceList,
        "give information about state of source": giveInformationAboutStateSource,
        "reject give information about state of source": rejectGiveInformationAboutStateSource,
    };

    try {
        if (objHandlerMsgInstraction[msg.instruction]) {
            objHandlerMsgInstraction[msg.instruction](msg);
        }
    } catch (err) {
        writeLogFile("error", `${err.toString()} (func 'handlerMsgSources')`);
    }
};

/**
 * Обработка сообщения с версией ПО ISEMS-NIH_slave
 * 
 * @param {*} msg 
 */
function sendVersionApp(msg) {
    //добавляем в БД
    require("../../libs/mongodb_requests/module_network_interaction/addVersionApp")(msg.options, (err) => {
        if (err) {
            throw err;
        }

        globalObject.modifyData("sources", msg.options.id, [
            ["appVersion", msg.options.av],
            ["appReleaseDate", msg.options.ard],
        ]);

        helpersFunc.sendBroadcastSocketIo("module-ni:send version app", {
            options: {
                sourceID: msg.options.id,
                appVersion: msg.options.av,
                appReleaseDate: msg.options.ard,
            }
        });
    });
}

/**
 * Обработчик изменения статуса соединения
 * 
 * @param {*} msg 
 */
function changeStatusSource(msg) {
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
            //отправить всем
            helpersFunc.sendBroadcastSocketIo("module-ni:change status source", {
                options: {
                    sourceID: item.id,
                    shortName: sourceInfo.shortName,
                    description: sourceInfo.description,
                    connectStatus: sourceInfo.connectStatus,
                    connectTime: sourceInfo.connectTime,
                    id: sourceInfo.id,
                    appVersion: "",
                    appReleaseDate: 0,
                }
            });
            helpersFunc.sendBroadcastSocketIo("module-ni:change sources connection", helpersFunc.getCountConnectionSources(globalObject));
        }
    });
}

/**
 * Здесь получаем список актуальных источников из базы
 * данных модуля сетевого взаимодействия.
 * 
 * @param {*} msg 
 */
function sendCurrentSourceList(msg) {
    /**
     *
     * Пока из него только извлекаем состояния сетевого соединения
     * источников и записываем в глобальный объект
     *
     */

    if (!Array.isArray(msg.options.sl)) {
        return;
    }

    let listSourceId = [];
    msg.options.sl.forEach((item) => {
        listSourceId.push(+item.id);

        const modifyIsSuccess = globalObject.modifyData("sources", item.id, [
            ["connectStatus", item.cs],
            ["connectTime", item.dlc]
        ]);

        // для источников которых нет в globalObject
        if (!modifyIsSuccess) {
            globalObject.setData("sources", item.id, {
                shortName: item.sn,
                description: item.d,
                connectStatus: item.cs,
                connectTime: item.dlc,
                id: "",
                appVersion: "",
                appReleaseDate: 0,
            });
        }
    });

    let sources = globalObject.getData("sources");
    for (let key in sources) {
        if (listSourceId.includes(+key)) {
            continue;
        }

        if (sources[key].id.length === 0) {
            globalObject.deleteData("sources", key);
        }
    }

    //отправить всем
    helpersFunc.sendBroadcastSocketIo("module-ni: short source list", {
        arguments: globalObject.getData("sources")
    });
}

/**
 * Обработчик сообщения с информацией о телеметрии
 * 
 * @param {*} msg 
 */
function giveInformationAboutStateSource(msg) {
    //проверяем отклонение локального времени источника
    let checkingDeviationLocalTime = () => {
        //если локальное время источника отличается больше чем на 59 мин. 
        return ((msg.options.i.currentDateTime < (+new Date - 3540000)) || (msg.options.i.currentDateTime > (+new Date + 3540000)));
    };

    //проверяем время последнего записанного файла
    let checkingTimeLastRecordedFile = () => {
        let storageTimeInterval = msg.options.i.timeInterval;
        let dateMin = 0;
        let dateMax = 0;

        for (let key in storageTimeInterval) {
            if (dateMin === 0 || dateMin > storageTimeInterval[key].dateMin) {
                dateMin = storageTimeInterval[key].dateMin;
            }

            if (dateMax < storageTimeInterval[key].dateMax) {
                dateMax = storageTimeInterval[key].dateMax;
            }
        }

        let behindCurrentTime = ((+new Date) <= dateMax) ? 0.0 : (+new Date - dateMax) / 3600000;

        return behindCurrentTime > 12;
    };

    let sourceInfo = globalObject.getData("sources", msg.options.id);

    //обрабатываем информацию о телеметрии
    globalObject.setData("telemetrySources", msg.options.id, {
        "timeReceipt": +new Date,
        "deviationParametersSource": (checkingDeviationLocalTime() || checkingTimeLastRecordedFile()),
        "shortSourceName": (sourceInfo === null) ? "" : sourceInfo.shortName,
        telemetryParameters: msg.options.i,
    });

    //получаем список источников у которых имеется отклонение параметров
    let listSourceDeviationParameters = [];
    let telemetrySources = globalObject.getData("telemetrySources");
    for (let sid in telemetrySources) {
        if (!telemetrySources[sid].deviationParametersSource) {
            continue;
        }

        listSourceDeviationParameters.push({
            sourceID: sid,
            shortSourceName: (sourceInfo === null) ? "" : sourceInfo.shortName,
            timeReceipt: telemetrySources[sid].timeReceipt,
            telemetryParameters: telemetrySources[sid].telemetryParameters,
        });
    }

    //отправляем информацию о телеметрии для виджета
    helpersFunc.sendBroadcastSocketIo("module NI API", {
        "type": "telemetryDeviationParameters",
        "options": listSourceDeviationParameters,
    });

    //    console.log("func 'giveInformationAboutStateSource', AFTER");
    //    console.log(telemetrySources);

    if (!globalObject.hasData("tasks", msg.taskID)) {
        helpersFunc.sendBroadcastSocketIo("module NI API", msg);
    }

    let taskInfo = globalObject.getData("tasks", msg.taskID);

    if (!helpersFunc.sendMessageByUserSocketIo(((taskInfo !== null) ? taskInfo.socketId : null), "module NI API", msg)) {
        helpersFunc.sendBroadcastSocketIo("module NI API", msg);
    }
}

/**
 * Обработчик сообщения с ошибками возникшими при обработке
 * запроса на получения телеметрии 
 * 
 * @param {*} msg 
 */
function rejectGiveInformationAboutStateSource(msg) {
    let listSourceDeviationParameters = globalObject.getData("telemetrySources");
    for (let num = 0; num < msg.options.sl.length; num++) {
        for (let sourceID in listSourceDeviationParameters) {
            if (+msg.options.sl[num].id !== +sourceID) {
                continue;
            }

            msg.options.sl[num].timeReceipt = listSourceDeviationParameters[sourceID].timeReceipt;
            msg.options.sl[num].telemetryParameters = listSourceDeviationParameters[sourceID].telemetryParameters;
        }
    }

    if (!globalObject.hasData("tasks", msg.taskID)) {
        helpersFunc.sendBroadcastSocketIo("module NI API", msg);
    }

    let taskInfo = globalObject.getData("tasks", msg.taskID);
    if (!helpersFunc.sendMessageByUserSocketIo(taskInfo.socketId, "module NI API", msg)) {
        helpersFunc.sendBroadcastSocketIo("module NI API", msg);
    }
}