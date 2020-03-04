/*
 * Записывает информацию в лог файл
 *
 * Версия 0.1, дата релиза 05.12.2018
 *
 * пример использования
 *
 * const writeLogFile = require('./writeLogFile');
 * writeLogFile('info', 'message');
 * writeLogFile('error', 'message');
 * */

"use strict";

const fs = require("fs");
const async = require("async");

class WriteLog {
    constructor(type, message) {
        this.type = type;
        this.message = message;
        this.currentDate = function() {
            return (new Date(Date.now() - ((new Date()).getTimezoneOffset() * 60000))).toISOString().slice(0, -1).replace(/T/, " ").replace(/\..+/, "");
        };
        this.dirRoot = __dirname.substr(0, (__dirname.length - 5));
        this.dirLog = "logs";
        this.pathLogFiles = `${this.dirRoot}/${this.dirLog}`;

        fs.lstat(this.pathLogFiles, err => {
            if (err) {
                fs.mkdir(this.pathLogFiles, err => {
                    if (err) console.log(err.toString());
                });
            }
        });
    }

    //пишем информационные сообщения
    write(nameFile, message, cb) {
        let self = this;
        let fileNameCurrentDate = self.currentDate().split(" ");
        let newFileName = `${fileNameCurrentDate[0]}_${fileNameCurrentDate[1]}_${nameFile}`;

        new Promise((resolve, reject) => {
            fs.appendFile(`${self.pathLogFiles}/${nameFile}`, message, err => {
                if (err) reject(err);
                else resolve();
            });
        }).then(() => {
            return new Promise((resolve, reject) => {
                fs.lstat(`${self.pathLogFiles}/${nameFile}`, (err, stats) => {
                    if (err) reject(err);
                    else resolve(stats);
                });
            });
        }).then(stats => {
            if (stats.size < 10000000) return cb(null);

            return new Promise((resolve, reject) => {
                fs.rename(
                    `${self.pathLogFiles}/${nameFile}`,
                    `${self.pathLogFiles}/${newFileName}`,
                    err => {
                        if (err) reject(err);
                        else resolve();
                    });
            });
        }).then(() => {
            return new Promise((resolve, reject) => {
                fs.appendFile(`${self.pathLogFiles}/${nameFile}`, "", { "encoding": "utf8" }, err => {
                    if (err) resolve(err);
                    else reject();
                });
            });
        }).then(() => {
            cb(null);
        }).catch(err => {
            return cb(err);
        });
    }
    /*       fs.appendFile(self.rootDirectory + nameFile, message, err => {
            if(err) return cb(err);

            fs.lstat(self.rootDirectory + nameFile, function(err, stats) {
                if(err) return cb(err);

                if(stats.size > 10000000){
                    fs.rename(
                        self.rootDirectory + nameFile,
                        self.rootDirectory + newFileName,
                        function (err) {
                            if(err) return func(err);

                            fs.appendFile(self.rootDirectory  + nameFile, '', { 'encoding': 'utf8' }, function(err) {
                                if(err) func(err);
                                else func(null);
                            });
                        }
                    );
                }
            });
        });
}*/

    //готовим сообщение
    messageInfo(cb) {
        let nameFile = `isems-ui-${this.type}.log`;
        let writeString = `${this.currentDate().toString()}\tINFO: ${this.message}\n`;

        this.write(nameFile, writeString, cb);
    }

    //пишем сообщение об ошибках
    messageError(cb) {
        let nameFile = `isems-ui-${this.type}.log`;
        let writeString = `${this.currentDate().toString()}\tERROR: ${this.message}\n`;

        this.write(nameFile, writeString, cb);
    }

    deleteOldLogFilesSync(objCountSafeFiles) {
        fs.readdir(this.pathLogFiles, (err, files) => {
            if (err) return console.log(err.toString());

            let obj = {};
            let arrayRemove = [];

            for (let typeFile in objCountSafeFiles) {
                obj[typeFile] = files.filter(item => (~item.indexOf(typeFile + ".log")));

                obj[typeFile].sort();
                let array = obj[typeFile].splice(0, obj[typeFile].length - objCountSafeFiles[typeFile]);
                arrayRemove = array.concat(arrayRemove);
            }

            async.forEach(arrayRemove, function(key, callbackForEach) {
                fs.unlink(`${this.pathLogFiles}/${key}`, err => {
                    if (err) callbackForEach(err);
                    else callbackForEach(null);
                });
            }, err => {
                if (err) console.log(err.toString());
            });
        });
    }
}

module.exports = function(type, message) {
    let writeLog = new WriteLog(type, message);

    //удаляем старые файлы
    writeLog.deleteOldLogFilesSync({
        info: 5,
        error: 10
    });

    let objTypeMessage = {
        "info": "messageInfo",
        "error": "messageError"
    };

    if (typeof writeLog[objTypeMessage[type]] === "undefined") {
        console.log("Error writing to log file message type not defined");

        return;
    }

    writeLog[objTypeMessage[type]](err => {
        if (err) console.log(`Error: ${err.toString()}`);
    });
};