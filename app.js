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

const options = {};

const credentials = {
    key: fs.readFileSync("keys/isems_ui_private_key.pem"),
    cert: fs.readFileSync("keys/isems_ui_cert.pem")
};

const server = https.createServer(credentials, app);
const io = require("socket.io").listen(server, options);

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

                        if (connectDB === null){
                            reject(new Error("the database connection is not established"));
                        } else { 
                            resolve(null);
                        }
                    });
                });
            }).then(() => {
                return new Promise((resolve, reject) => {
                    //проверяем наличие и при необходимости создаем схемы MongoDB
<<<<<<< HEAD
=======
                    debug("create MongoDB schemes");
                    debug("create MongoDB schemes");


>>>>>>> 514794058843b47276a29ae8cf998f9170dc9433
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
    *       соединение с модулем ISEMS-NIH
    * модуль сетевого взаимодействия с источниками
    */
    (callback) => {
        console.log("\x1b[32m%s\x1b[0m", "Debug:", "Initializing the connection to the network interface module");
        
        //настраиваем дескриптор соединения с модулем
        globalObject.setData(
            "descriptionAPI", 
            "networkInteraction", {
                "connection": networkInteractionHandlerAPI({
                    ip: config.get("modules:networkInteraction:host"),
                    port: config.get("modules:networkInteraction:port"),
                    token: config.get("modules:networkInteraction:token")
                }),
                "connectionEstablished": false,
            });
     
        //настраиваем хранилище задач выполняемые модулем
        globalObject.setData("tasks", {});
        //устанавливаем временное хранилище для информации о задачах фильтрации
        // и выгрузки фалов полученных из модуля сет. взаимодействия. 
        // Доступ к хранилищу по sessionId пользователя
        globalObject.setData("tmpModuleNetworkInteraction", {});

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
        console.log("\x1b[31m%s\x1b[0m", "ERROR: the server cannot start, there is an error in the configuration, details in the log file");
        writeLogFile("error", err.toString());

        process.exit(1);
    }

    //запуск HTTPS сервера
    server.listen({
        port: config.get("httpServer:port"),
        host: config.get("httpServer:host")
    }, () => {
        //формируем список источников в globalObject
        require("./libs/management_settings/createSourceListForGlobalObject")()
            .then(() => {
                return new Promise((resolve,reject) => {
                    figlet.text("ISEMS-UI", (err, title) => {
                        if (err) reject(err);

                        console.log(title);
                        console.log("\x1b[32m%s\x1b[0m", "Debug:", `start ISEMS-UI app, server listening on port ${config.get("httpServer:port")}, host ${config.get("httpServer:host")}`);

                        writeLogFile("info", `start ISEMS-UI app, server listening on port ${config.get("httpServer:port")}, host ${config.get("httpServer:host")}`);

                        resolve();
                    });
                });
            }).then(() => {             
                //настраиваем сервер
                require("./middleware")(app, express, io);
            }).catch((err) => {
                console.log(err);
            });
    });
});