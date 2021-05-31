/**
 * Точка входа для приложения ISEMS_UI
 *
 * Версия 1.0, дата релиза 16.04.2020
 */

"use strict";

const fs = require("fs");
const async = require("async");
const https = require("https");
const figlet = require("figlet");
const express = require("express");

const app = express();
const config = require("./configure");
const globalObject = require("./configure/globalObject");
const writeLogFile = require("./libs/writeLogFile");
const connectMongoDB = require("./controllers/connectMongoDB");
const createSchemasMongoDB = require("./controllers/createSchemasMongoDB");
const networkInteractionHandlerAPI = require("./middleware/networkInteractionHandlerAPI");
const managingRecordsStructuredInformationAboutComputerThreatsAPI = require("./middleware/managingRecordsStructuredInformationAboutComputerThreatsAPI");

const server = https.createServer({
    key: fs.readFileSync(config.get("httpServer:keysPath:privateKey")),
    cert: fs.readFileSync(config.get("httpServer:keysPath:cert")),
}, app);

const options = {};
const io = require("socket.io")(server, options);

new Promise((resolve, reject) => {
    figlet.text("ISEMS-UI", (err, title) => {
        if (err) {
            reject(err);
        }

        console.log(title);
        resolve();
    });
}).then(() => {
    async.parallel([
        /* устанавливаем соединение с СУБД MongoDB */
        (callback) => {
            console.log("\x1b[32m%s\x1b[0m", "Debug:", "Initializing a connection to the MongoDB database");

            connectMongoDB()
                .then((description) => {
                    return new Promise((resolve, reject) => {
                        process.nextTick(() => {
                            globalObject.setData("descriptionDB", "MongoDB", {
                                "connection": description,
                                "connectionTimestamp": +new Date(),
                                "userName": config.get("mongoDB:user")
                            });

                            let connectDB = globalObject.getData("descriptionDB", "MongoDB", "connection");

                            if (connectDB === null) {
                                reject(new Error("the database connection is not established"));
                            } else {
                                resolve(null);
                            }
                        });
                    });
                }).then(() => {
                    return new Promise((resolve, reject) => {
                        //проверяем наличие и при необходимости создаем схемы MongoDB
                        createSchemasMongoDB(err => {
                            if (err) reject(err);
                            else resolve(null);
                        });
                    });
                }).then(() => {
                    return require("./libs/mongodb_requests/getUsersSessionInformation")();
                }).then((listUserSession) => {
                    for (let sessionId in listUserSession) {
                        globalObject.setData("users", sessionId, listUserSession[sessionId]);
                    }

                    callback(null);
                }).catch((err) => {
                    callback(err);
                });
        },
        /**
         *       соединение с модулем ISEMS-NIH (модуль сетевого взаимодействия с источниками)
         */
        (callback) => {
            console.log("\x1b[32m%s\x1b[0m", "Debug:", "Initializing the connection to ISEMS-NIH module");

            //настраиваем дескриптор соединения с API модуля networkInteractionHandler 
            globalObject.setData(
                "descriptionAPI",
                "networkInteraction", {
                    "connection": networkInteractionHandlerAPI({
                        ip: config.get("modules:networkInteraction:host"),
                        port: config.get("modules:networkInteraction:port"),
                        token: config.get("modules:networkInteraction:token")
                    }),
                    "connectionEstablished": false,
                    "previousConnectionStatus": false,
                });

            callback(null);
        },
        /**
         *       соединение с модулем ISEMS-MRSICT (модуль управления записями структурированной информации о компьютерных угрозах)
         */
        (callback) => {
            console.log("\x1b[32m%s\x1b[0m", "Debug:", "Initializing the connection to ISEMS-MRSICT module");

            globalObject.setData(
                "descriptionAPI",
                "managingRecordsStructuredInformationAboutComputerThreats", {
                    "connection": managingRecordsStructuredInformationAboutComputerThreatsAPI({
                        ip: config.get("modules:managingRecordsStructuredInformationAboutComputerThreats:host"),
                        port: config.get("modules:managingRecordsStructuredInformationAboutComputerThreats:port"),
                        token: config.get("modules:managingRecordsStructuredInformationAboutComputerThreats:token")
                    }),
                    "connectionEstablished": false,
                    "previousConnectionStatus": false,
                });

            callback(null);
        },
        /**
         * соединение с модулем ISEMS-AIM (модуль управление аналитической информацией) 
         * 
         * !!! пока как заглушка, подобного модуля нет !!! 
         */
        (callback) => {
            //console.log("\x1b[32m%s\x1b[0m", "Debug:", "Initializing the connection to ISEMS-MRSICT module");

            globalObject.setData(
                "descriptionAPI",
                "analyticalInformationManagement", {
                    "connection": {}, /*managingRecordsStructuredInformationAboutComputerThreatsAPI({
                        ip: config.get("modules:managingRecordsStructuredInformationAboutComputerThreats:host"),
                        port: config.get("modules:managingRecordsStructuredInformationAboutComputerThreats:port"),
                        token: config.get("modules:managingRecordsStructuredInformationAboutComputerThreats:token")
                    })*/
                    "connectionEstablished": false,
                    "previousConnectionStatus": false,
                });

            callback(null);
        },
        /* устанавливаем общие настройки приложения */
        (callback) => {
            process.nextTick(() => {
                let listFieldActivity = config.get("appSettings:listFieldActivity");
                listFieldActivity.sort();
                listFieldActivity.push("иная деятельность");

                globalObject.setData("commonSettings", "listFieldActivity", listFieldActivity);

                callback(null);
            });
        }
    ], (err) => {
        if (err) {
            throw err;
        }

        //запуск HTTPS сервера
        server.listen({
            port: config.get("httpServer:port"),
            host: config.get("httpServer:host")
        }, () => {
            //формируем список источников в globalObject
            require("./libs/management_settings/createSourceListForGlobalObject")()
                .then(() => {
                    console.log("\x1b[32m%s\x1b[0m", "Debug:", `start ISEMS-UI app, server listening on port ${config.get("httpServer:port")}, host ${config.get("httpServer:host")}`);

                    writeLogFile("info", `Start ISEMS-UI app, server listening on port ${config.get("httpServer:port")}, host ${config.get("httpServer:host")}`);

                    //настраиваем сервер
                    require("./middleware")(app, express, io);
                }).catch((err) => {
                    console.log(err);
                });
        });
    });
}).catch((err) => {
    console.log("\x1b[31m%s\x1b[0m", "ERROR: the server cannot start, there is an error in the configuration, details in the log file");
    writeLogFile("error", err.toString());

    process.exit(1);
});