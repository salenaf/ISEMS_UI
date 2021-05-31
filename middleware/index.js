"use strict";

const ejs = require("ejs-locals");
const path = require("path");

const helmet = require("helmet");
const favicon = require("serve-favicon");
const session = require("express-session");
const passport = require("passport");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const errorHandler = require("errorhandler");
const cookieParser = require("cookie-parser");
const LocalStrategy = require("passport-local").Strategy;
const MongoStore = require("connect-mongo")(session);

const routes = require("../routes");
const helpersFunc = require("../libs/helpers/helpersFunc");
const globalObject = require("../configure/globalObject");
const writeLogFile = require("../libs/writeLogFile");
const routeSocketIo = require("../routes/routeSocketIo");
const AuthenticateStrategy = require("./authenticateStrategy");

module.exports = function (app, express, io) {
    //срок окончания хранения постоянных cookie 7 суток
    let ttl = (60 * 60 * 24 * 7);
    let funcName = " (middleware/index.js)";


    /**
     * помогает защитить приложение от некоторых широко известных веб-уязвимостей путем соответствующей настройки заголовков HTTP
     */
    app.use(helmet());

    /*
     * Rendering pages
     * */
    app.engine("html", ejs);
    app.engine("ejs", ejs);
    app.set("views", path.join(__dirname, "../views"));
    app.set("view engine", "ejs");
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(cookieParser());

    /*!!!!! ДЛЯ РАЗРАБОТКИ ВЫКЛЮЧЕН !!!!!*/
    app.disable("view cache");
    /*!!!! В ПРОДАКШЕНЕ ДОЛЖЕН БЫТЬ ВКЛЮЧЕН ИЛИ ЗАКОМЕНТЕН !!!!!*/

    /*
     * Favicon
     * */
    app.use(favicon(path.join(__dirname, "../public/images/favicon.ico")));

    /*
     * Session
     * */
    app.use(session({
        secret: "isems_ui_app",
        name: "sessionId",
        resave: false,
        saveUninitialized: false, //Не помещать в БД пустые сессии
        maxAge: ttl * 1000,
        store: new MongoStore({ //хранилище сеансов (сессий) основанное на connect-mongo
            mongooseConnection: mongoose.connection,
            ttl: ttl,
            autoRemove: "native" //Default
        }),
        cookie: {
            secure: true, //обеспечивает отправку файлов cookie браузером только с использованием протокола HTTPS.
            httpOnly: true, //обеспечивает отправку cookie только с использованием протокола HTTP(S), а не клиентского JavaScript, что способствует защите от атак межсайтового скриптинга.
            //domain - указывает домен cookie; используется для сравнения с доменом сервера, на котором запрашивается данный URL. В случае совпадения выполняется проверка следующего атрибута - пути.
            //path - указывает путь cookie; используется для сравнения с путем запроса. Если путь и домен совпадают, выполняется отправка cookie в запросе.
        },
    }));

    /*
     * Passportjs initialization
     * */
    app.use(passport.initialize());
    app.use(passport.session());

    /**
     * Timer temp task
     */
    const eventEmiterTimerTick = require("./handlerTimerTick")(60000);

    /*
     * Socket.io
     * */
    let socketIo = io.sockets.on("connection", function (socket) {
        globalObject.setData("descriptionSocketIo", "userConnections", socket.id, socket);

        console.log(`socketIo CONNECTION with id: '${socket.id}'`);

        //обработчик событий User Interface
        routeSocketIo.eventHandlingUserInterface(eventEmiterTimerTick, socket);

        socket.on("disconnect", () => {
            console.log(`socketIo DISCONNECT with id: '${socket.id}'`);

            globalObject.deleteData("descriptionSocketIo", "userConnections", socket.id);
        });
    });

    globalObject.setData("descriptionSocketIo", "majorConnect", socketIo);

    /*
     * Public directory
     * */
    app.use(express.static(path.join(__dirname, "../public")));
    app.use("/public", express.static(path.join(__dirname, "../public")));

    /*
     * Routing
     * */
    routes(app);

    /* 
     * Module Network Interaction Handler (ISEMS-NIH) 
     * */
    (() => {
        const TIME_INTERVAL = 7000;

        if (globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            return;
        }

        let connection = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        connection.createAPIConnection()
            .on("connect", () => {
                writeLogFile("info", `Connection with module 'Network Interaction Handler' ${funcName}`);

                helpersFunc.sendBroadcastSocketIo("module NI API", {
                    type: "connectModuleNI",
                    options: { connectionStatus: true },
                });

                globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished", true);
                globalObject.setData("descriptionAPI", "networkInteraction", "previousConnectionStatus", true);
            })
            .on("connectFailed", (err) => {
                writeLogFile("error", err.toString() + funcName);
            })
            .on("error message", (msg) => {
                writeLogFile("error", msg.toString() + funcName);
            })
            .on("close", (msg) => {
                writeLogFile("info", msg.toString() + funcName);

                helpersFunc.sendBroadcastSocketIo("module NI API", {
                    type: "connectModuleNI",
                    options: { connectionStatus: false },
                });

                globalObject.modifyData("descriptionAPI", "networkInteraction", [
                    ["connectionEstablished", false],
                    ["previousConnectionStatus", false]
                ]);

                setTimeout((() => {
                    if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                        connection.createAPIConnection();
                    }
                }), TIME_INTERVAL);
            })
            .on("error", (err) => {
                writeLogFile("error", err.toString() + funcName);

                helpersFunc.sendBroadcastSocketIo("module NI API", {
                    type: "connectModuleNI",
                    options: { connectionStatus: false },
                });

                globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished", false);
                globalObject.setData("descriptionAPI", "networkInteraction", "previousConnectionStatus", false);

                setTimeout((() => {
                    if (!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                        connection.createAPIConnection();
                    }
                }), TIME_INTERVAL);
            });
    })();

    /* 
     * Module Managing Records of Structured Information About Computer Threats (ISEMS-MRSICT)
     * */
    (() => {
        const TIME_INTERVAL = 7000;

        if (globalObject.getData("descriptionAPI", "managingRecordsStructuredInformationAboutComputerThreats", "connectionEstablished")) {
            return;
        }

        let connection = globalObject.getData("descriptionAPI", "managingRecordsStructuredInformationAboutComputerThreats", "connection");
        connection.createAPIConnection()
            .on("connect", () => {
                console.log("func 'middleware', CONNECTION to module 'ISEMS-MRSICT'");

                writeLogFile("info", `Connection with module 'Managing Records Structured Information About Computer Threats' ${funcName}`);

                helpersFunc.sendBroadcastSocketIo("module_MRSICT-API", {
                    type: "connectModuleMRSICT",
                    options: { connectionStatus: true },
                });

                globalObject.modifyData("descriptionAPI", "managingRecordsStructuredInformationAboutComputerThreats", [
                    ["connectionEstablished", true],
                    ["previousConnectionStatus", true]
                ]);
            })
            .on("connectFailed", (err) => {
                console.log("func 'middleware', CONNECT FAILED, module 'ISEMS-MRSICT'");
                console.log(err);

                writeLogFile("error", err.toString() + funcName);
            })
            .on("error message", (msg) => {
                console.log("func 'middleware', ERROR MESSAGE, module 'ISEMS-MRSICT'");
                console.log(msg);

                writeLogFile("error", msg.toString() + funcName);
            })
            .on("close", (msg) => {
                console.log("func 'middleware', CONNECTION CLOSE with module 'ISEMS-MRSICT'");
                console.log(msg);

                writeLogFile("info", msg.toString() + funcName);

                helpersFunc.sendBroadcastSocketIo("module_MRSICT-API", {
                    type: "connectModuleMRSICT",
                    options: { connectionStatus: false },
                });

                globalObject.modifyData("descriptionAPI", "managingRecordsStructuredInformationAboutComputerThreats", [
                    ["connectionEstablished", false],
                    ["previousConnectionStatus", false]
                ]);

                setTimeout((() => {
                    if (!globalObject.getData("descriptionAPI", "managingRecordsStructuredInformationAboutComputerThreats", "connectionEstablished")) {
                        connection.createAPIConnection();
                    }
                }), TIME_INTERVAL);
            })
            .on("error", (err) => {
                console.log("func 'middleware', ERROR, module 'ISEMS-MRSICT'");
                console.log(err);

                writeLogFile("error", err.toString() + funcName);

                helpersFunc.sendBroadcastSocketIo("module_MRSICT-API", {
                    type: "connectModuleMRSICT",
                    options: { connectionStatus: false },
                });

                globalObject.modifyData("descriptionAPI", "managingRecordsStructuredInformationAboutComputerThreats", [
                    ["connectionEstablished", false],
                    ["previousConnectionStatus", false]
                ]);

                setTimeout((() => {
                    if (!globalObject.getData("descriptionAPI", "managingRecordsStructuredInformationAboutComputerThreats", "connectionEstablished")) {
                        connection.createAPIConnection();
                    }
                }), TIME_INTERVAL);
            });
    })();

    //обработчик событий сторонних модулей через API
    require("../routes/routeModulesEvent").modulesEventGenerator(socketIo);
    //routeSocketIo.modulesEventGenerator(eventEmiterTimerTick, socketIo);

    /**
     * Restoring information from a database
     */
    require("../libs/restoringInformationFromDatabase")(eventEmiterTimerTick).catch((err) => {
        writeLogFile("error", err.toString() + " (restoringInformationFromDatabase.js)");
    });

    /*
     * Setup passport
     * */
    passport.use(new LocalStrategy({
        usernameField: "login",
        passwordField: "password"
    }, AuthenticateStrategy.authenticate));
    passport.serializeUser(AuthenticateStrategy.serializeUser);
    passport.deserializeUser(AuthenticateStrategy.deserializeUser);

    /*
     * Response error
     * */
    app.use(errorHandler());
};