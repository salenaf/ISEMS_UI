/**
 * Полное удаление всех директорий в заданном катологе
 * 
 * @param {*} pathDirectoryStart - начальная директория из которой удаляются все вложенные директории
 * @param {*} func - функция обратоного вызова
 * 
 * Версия 0.1, дата релиза 11.01.2018
 */

'use strict';

const fs = require('fs');
const path = require('path');
const async = require('async');

module.exports = function(pathDirectoryStart, func) {
    let arrayDir = [];

    filesDelete(pathDirectoryStart, (err) => {
        if (err) return func(err);

        arrayDir.reverse();
        async.each(arrayDir, (dirName, callback) => {
            fs.rmdir(dirName, (err) => {
                if (err) callback(err);
                else callback(null);
            });
        }, function(err) {
            if (err) func(err);
            else func(null);
        });
    });

    function filesDelete(pathDir, done) {
        fs.readdir(pathDir, (err, files) => {
            if (err) return done(err);

            async.eachSeries(files, (fileName, callbackEachSeries) => {
                let filePath = path.join(pathDir, fileName);

                fs.stat(filePath, (err, stats) => {
                    if (err) return callbackEachSeries(err);

                    if (stats.isDirectory()) {
                        arrayDir.push(filePath);

                        filesDelete(filePath, (err, subDirFiles) => {
                            if (err) return callbackEachSeries(err);

                            filePath = filePath.concat(subDirFiles);
                            callbackEachSeries(null);
                        });
                    } else {
                        if (stats.isFile()) {
                            fs.unlink(filePath, (err) => {
                                if (err) callbackEachSeries(err);
                                else callbackEachSeries(null);
                            });
                        }
                    }
                });
            }, function(err) {
                if (err) done(err);
                else done(null, arrayDir);
            });
        });
    }
};