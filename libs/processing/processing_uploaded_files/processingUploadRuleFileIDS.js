/*
 * Обработка файла содержащего правила СОА
 *
 * - проверка расширения файла
 * - разархивирование файла в формате tar.gz во временную директорию
 * - парсинг разархивированных файлов и загрузка их в СУБД MongoDB
 *
 * Версия 0.2, дата релиза 11.01.2018
 * */

'use strict';

const fs = require('fs');
const path = require('path');
const async = require('async');
const tarGzip = require('node-targz');

const models = require('../../../controllers/models');
const getSessionId = require('../../helpers/getSessionId');
const writeLogFile = require('../../writeLogFile');
const fullDirectoryDelete = require('../../helpers/fullDirectoryDelete');

module.exports = function(socketIo, fileName, pathFolder, func) {
    let folderTmp = +new Date() + '_uploaded_rules_tmp';
    let pathFolderZip = path.join(pathFolder, fileName);
    let pathFolderUnZip = path.join(pathFolder, folderTmp);

    async.waterfall([
        function(callback) {
            if (!(~fileName.indexOf('tar.gz'))) callback(new Error('the received file is invalid'));
            else callback(null);
        },
        //разархивируем файл
        function(callback) {
            tarGzip.decompress({
                source: pathFolderZip,
                destination: pathFolderUnZip
            }, (err) => {
                if (err) callback(err);
                else callback(null, pathFolderZip, pathFolderUnZip);
            });
        },
        //получаем список разархивированных файлов
        function(pathFolderZip, pathFolderUnZip, callback) {
            getFiles(pathFolderUnZip, (err, listFiles) => {
                if (err) callback(err);
                else callback(null, pathFolderZip, listFiles);
            });

            let arrayFiles = [];

            function getFiles(pathFolderUnzipFiles, done) {
                fs.readdir(pathFolderUnzipFiles, (err, files) => {
                    if (err) return done(err);

                    async.eachSeries(files, (fileName, callbackEachSeries) => {
                        let filePath = path.join(pathFolderUnzipFiles, fileName);

                        fs.stat(filePath, (err, stats) => {
                            if (err) return callbackEachSeries(err);

                            if (stats.isDirectory()) {
                                getFiles(filePath, (err, subDirFiles) => {
                                    if (err) return callbackEachSeries(err);

                                    filePath = filePath.concat(subDirFiles);
                                    callbackEachSeries(null);
                                });
                            } else {
                                if (stats.isFile() && /\.rules$/.test(filePath)) {
                                    arrayFiles.push(filePath);
                                }
                                callbackEachSeries(null);
                            }
                        });
                    }, function(err) {
                        if (err) done(err);
                        else done(null, arrayFiles);
                    });
                });
            }
        },
        //удалаем файл-архив
        function(pathFolderZip, arrayFiles, callback) {
            fs.unlink(pathFolderZip, function(err) {
                if (err) callback(err);
                else callback(null, arrayFiles);
            });
        },
        //получаем логин и имя пользователя
        function(arrayFiles, callback) {
            getSessionId('socketIo', socketIo, function(err, sessionId) {
                if (err) return callback(err);

                models.modelSessionUserInformation.findOne({ session_id: sessionId }, { _id: 0, login: 1, user_name: 1 },
                    function(err, obj) {
                        if (err) callback(err);
                        else callback(null, arrayFiles, obj);
                    });
            });
        }
    ], function(err, arrayFiles, objUser) {
        if (err) {
            writeLogFile('error', err.toString());
            return func(err);
        }

        let countAllRules = 0;
        let numberFile = 0;
        let dbInsert = function(arrayString, number, callback) {
            let lengthArrayString = (arrayString.length - 1);
            if (lengthArrayString <= number) return callback(null);

            if (!(~arrayString[number].indexOf('alert'))) {
                dbInsert(arrayString, ++number, callback);
            }

            let msg = arrayString[number].match(/\(msg:"(.+?(?=";\s+))/i);
            let classType = arrayString[number].match(/\bclasstype:([\w-]+?(?=;\s+))/);
            let sid = arrayString[number].match(/\bsid:(\d+?(?=;\s+))/);

            let msgIsExist = (msg !== null && typeof msg.length !== 'undefined' && msg.length > 1);
            let classTypeIsExist = (classType !== null && typeof classType.length !== 'undefined' && classType.length > 1);
            let sidIsExist = (sid !== null && typeof sid.length !== 'undefined' && sid.length > 1);

            if (msgIsExist && classTypeIsExist && sidIsExist) {
                models.modelRulesIDS.collection.insert({
                    'sid': +sid[1],
                    'classType': classType[1],
                    'msg': msg[1],
                    'body': arrayString[number]
                }, function(err) {
                    if (err) {
                        if (err.code === 11000) dbInsert(arrayString, ++number, callback);
                        else callback(err);
                    } else {
                        countAllRules++;
                        dbInsert(arrayString, ++number, callback);
                    }
                });
            } else {
                dbInsert(arrayString, ++number, callback);
            }
        };

        async.each(arrayFiles, function(pathFile, callbackEachOfOne) {
            fs.readFile(pathFile, 'utf8', (err, data) => {
                if (err) return callbackEachOfOne(err);

                let arrayString = data.split('\r\n');

                fs.unlink(pathFile, function(err) {
                    if (err) writeLogFile('error', err.toString());
                });

                dbInsert(arrayString, 0, (err) => {
                    if (err) return callbackEachOfOne(err);

                    let arrayTmp = pathFile.split('/');
                    let fileName = arrayTmp[arrayTmp.length - 1];

                    socketIo.emit('uploaded files', {
                        processing: 'load',
                        typeFile: 'ids rules',
                        name: fileName,
                        number: ++numberFile,
                        count: arrayFiles.length
                    });

                    callbackEachOfOne(null);
                });
            });
        }, function(err) {
            if (err) {
                writeLogFile('error', err.toString());
                return func(err);
            }

            return new Promise((resolve, reject) => {
                models.modelRulesIDS.find({}, { _id: 1 }, (err, document) => {
                    if (err) reject(err);

                    models.modelAdditionalInformation.update({
                        'ids_rules.create_date': +new Date(),
                        'ids_rules.create_login': objUser.login,
                        'ids_rules.create_username': objUser.user_name,
                        'ids_rules.count_rules': document.length
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            })
                .then(() => {
                    return new Promise((resolve, reject) => {
                        //удаление всех под директорий в указанной директории
                        fullDirectoryDelete('/home/development/waterfall-UI/uploads/', (err, arrayDir) => {
                            if (err) writeLogFile('error', err.toString());
                            resolve();
                        });
                    });
                })
                .then(() => {
                    writeLogFile('info', 'rules update IDS, all processed files still ' + countAllRules);

                    socketIo.emit('uploaded files', {
                        processing: 'completed',
                        typeFile: 'ids rules'
                    });

                    func(null, countAllRules);
                })
                .catch(err => {
                    writeLogFile('error', err.toString());

                    func(err);
                });


            //удаление всех под директорий в указанной директории
            /*function directoryDelete(pathDirectoryStart, func) {
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
            }*/
        });
    });
};