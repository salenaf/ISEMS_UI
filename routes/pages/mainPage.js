/*
 * Формирование данных для главной страници приложения
 *
 * Верися 0.1, дата релиза 31.03.2017
 * */

'use strict';

const async = require('async');

const globalObject = require('../../configure/globalObject');
const writeLogFile = require('../../libs/writeLogFile');
const getListDashboardSource = require('../../libs/mongodb_requests/getListDashboardSource');

module.exports = function(req, res, objHeader) {
    async.parallel({
        //список источников
        listSources: function(callback) {
            let objFinal = {};
            /*let arraySources = Object.keys(objGlobals.sources.sourceAvailability);
            arraySources.sort();

            arraySources.forEach((sourceId) => {
                objFinal[sourceId] = {
                    shortName: objGlobals.sources.sourceAvailability[sourceId].shortName,
                    detailedDescription: objGlobals.sources.sourceAvailability[sourceId].detailedDescription,
                    statusConnection: objGlobals.sources.sourceAvailability[sourceId].statusNew
                };
            });*/
            callback(null, objFinal);
        },
        //список дачбордов источников
        listSourceDashboard: function(callback) {
            /*getListDashboardSource(req, function(err, arraySource) {
                if (err) callback(err);
                else callback(null, arraySource);
            });*/

            callback(null, []);
        }
    }, function(err, result) {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('index', {
                header: {},
                listSources: {},
                listSourceDashboard: {}
            });
        } else {
            res.render('index', {
                header: objHeader,
                listSources: result.listSources,
                listSourceDashboard: result.listSourceDashboard
            });
        }
    });
};