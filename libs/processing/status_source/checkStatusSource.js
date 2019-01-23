/*
 * Изменение статуса источников
 *
 * Версия 0.1, дата релиза 27.04.2017
 * */

'use strict';

const objGlobals = require('../../../configure/globalObject');

module.exports = function(socketIo) {
    let objFinal = {};
    let arraySources = Object.keys(objGlobals.sources.sourceAvailability);
    arraySources.sort();

    arraySources.forEach((sourceId) => {
        objFinal[sourceId] = {
            shortName: objGlobals.sources.sourceAvailability[sourceId].shortName,
            statusConnection: objGlobals.sources.sourceAvailability[sourceId].statusNew
        };
    });

    socketIo.emit('changeStatusSource', objFinal);
};