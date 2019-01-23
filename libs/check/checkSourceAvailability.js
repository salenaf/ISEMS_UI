/*
 * Контроль доступности источников статистики netflow
 *
 * Версия 0.1, дата релиза 26.04.2017
 * */

'use strict';

const config = require('../../configure');
const objGlobals = require('../../configure/globalObject');
const routeSocketIo = require('../../routes/routeSocketIo');

/*
 objGlobal.sources.sourceAvailability[<идентификатор_источника>] = {
     shortName: item.short_name,
     updateFrequency: item.update_frequency,
     dateLastUpdate: null,
     statusOld: false,
     statusNew: false
 };
 */

module.exports = function(io) {
    setInterval(checkSourceAvailability.bind(null, io), config.get('timerCheckSourceAvailability'));
};

function checkSourceAvailability(io) {

    console.log('--- CHECK AVAILABILITY ---');

    let sources = objGlobals.sources.sourceAvailability;

    for (let sourceId in sources) {
        if (sources[sourceId].dateLastUpdate === null) continue;

        let countSec = 1;
        if (sources[sourceId].updateFrequency >= 30 && 60 >= sources[sourceId].updateFrequency) countSec = 5;
        else if (sources[sourceId].updateFrequency >= 61 && 120 >= sources[sourceId].updateFrequency) countSec = 10;
        else if (sources[sourceId].updateFrequency >= 121 && 240 >= sources[sourceId].updateFrequency) countSec = 15;
        else if (sources[sourceId].updateFrequency >= 241) countSec = 30;

        //проверяем частоту обновления
        sources[sourceId].statusNew = (sources[sourceId].dateLastUpdate >= (+new Date() - (sources[sourceId].updateFrequency + countSec) * 1000));

        //проверяем изменение статуса
        if (sources[sourceId].statusOld === sources[sourceId].statusNew) continue;

        sources[sourceId].statusOld = sources[sourceId].statusNew;
        //генерируем событие информирующее о изменении статуса источников
        routeSocketIo.eventEmitter(io, { type: 'changingStatusSource' });
    }

}