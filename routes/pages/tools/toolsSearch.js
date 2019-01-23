/*
 * Формирование страницы поиска информации
 *
 * Верися 0.1, дата релиза 23.01.2019
 * */

'use strict';

const async = require('async');

const writeLogFile = require('../../../libs/writeLogFile');

/*
 const informationForHeader = require('../../libs/informationForHeader');
 const shortNameIdRemoteHosts = require('../../libs/shortNameIdRemoteHosts');
 const informationForMainPage = require('../../libs/informationForMainPage');
 const informationForLeftContent = require('../../libs/informationForLeftContent');
 const informationForRightContent = require('../../libs/informationForRightContent');
 */
module.exports = function(req, res, objHeader) {

    console.log(objHeader);

    async.parallel({
        test: function(callback) {
            callback(null, {});
        }
    }, function(err) {
        if (err) {
            writeLogFile('error', err.toString());
            res.render('menu/tools/search_tools', {});
        } else {
            res.render('menu/tools/search_tools', {
                header: objHeader
            });
        }
    });
};