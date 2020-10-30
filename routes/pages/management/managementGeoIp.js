/*
 * Страница управления GeoIP
 *
 * Верися 0.1, дата релиза 27.07.2017
 * */

"use strict";

const async = require("async");

const writeLogFile = require("../../../libs/writeLogFile");

module.exports = function(req, res, objHeader) {
    async.parallel({
        test: function(callback) {
            callback(null, {});
        }
    }, function(err) {
        if (err) {
            writeLogFile("error", err.toString());
            res.render("menu/settings/setting_geoip", {});
        } else {
            res.render("menu/settings/setting_geoip", {
                header: objHeader
            });
        }
    });
};