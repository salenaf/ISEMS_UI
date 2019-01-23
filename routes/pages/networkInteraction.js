/*
 * Формирование страницы сетевых взаимодействий с удаленными источниками
 *
 * Верися 0.1, дата релиза 17.01.2019
 * */

'use strict';

const async = require('async');

const writeLogFile = require('../../libs/writeLogFile');

/*
 const informationForHeader = require('../../libs/informationForHeader');
 const shortNameIdRemoteHosts = require('../../libs/shortNameIdRemoteHosts');
 const informationForMainPage = require('../../libs/informationForMainPage');
 const informationForLeftContent = require('../../libs/informationForLeftContent');
 const informationForRightContent = require('../../libs/informationForRightContent');
 */
module.exports = function(req, res, objHeader) {
    async.parallel({
        test: function(callback) {
            callback(null, {});
        }
    }, function(err) {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('menu/network_interaction', {});
        } else {
            res.render('menu/network_interaction', {
                header: objHeader
            });
        }
    });
};