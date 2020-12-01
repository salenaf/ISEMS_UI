/*
 * Настройка express
 *
 * Версия 0.1, дата релиза 14.01.2019
 * */

"use strict";

module.exports = function(app, express, io) {
    //    const ss = require("socket.io-stream");
    const ejs = require("ejs-locals");
    const path = require("path");

    //const logger = require('morgan');

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
    const globalObject = require("../configure/globalObject");
    const writeLogFile = require("../libs/writeLogFile");
    const routeSocketIo = require("../routes/routeSocketIo");
    const AuthenticateStrategy = require("./authenticateStrategy");

    //срок окончания хранения постоянных cookie 14 суток
    let expiresDate = new Date(Date.now() + ((60 * 60 * 24 * 14) * 1000));
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
        saveUninitialized: false, //true,
        maxAge: 259200000,
        store: new MongoStore({ //хранилище сеансов (сессий) основанное на connect-mongo
            mongooseConnection: mongoose.connection,
            ttl: 14 * 24 * 60 * 60, // = 14 суток. Default
            autoRemove: "native" //Default
        }),
        cookie: {
            secure: true, //обеспечивает отправку файлов cookie браузером только с использованием протокола HTTPS.
            httpOnly: true, //обеспечивает отправку cookie только с использованием протокола HTTP(S), а не клиентского JavaScript, что способствует защите от атак межсайтового скриптинга.
            //domain - указывает домен cookie; используется для сравнения с доменом сервера, на котором запрашивается данный URL. В случае совпадения выполняется проверка следующего атрибута - пути.
            //path - указывает путь cookie; используется для сравнения с путем запроса. Если путь и домен совпадают, выполняется отправка cookie в запросе.
            expires: expiresDate, //используется для настройки даты окончания срока хранения для постоянных cookie.
        },
    }));

    /*
     * Passportjs initialization
     * */
    app.use(passport.initialize());
    app.use(passport.session());

    /*
     * Socket.io
     * */
    let socketIo = io.sockets.on("connection", function(socket) {
        globalObject.setData("descriptionSocketIo", "userConnections", socket.id, socket);

        //console.log(`socketIo CONNECTION with id: '${socket.id}'`);

        //обработчик событий User Interface
        routeSocketIo.eventHandlingUserInterface(socket);

        socket.on("disconnect", () => {
            //console.log(`socketIo DISCONNECT with id: '${socket.id}'`);

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
     * Module network interaction 
     * */
    let connectionWithModuleNetworkInteraction = () => {
        const TIME_INTERVAL = 7000;

        //        console.log("func 'connectionWithModuleNetworkInteraction'");
        //        console.log(`connectionEstablished status: ${globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")}`);

        if (globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
            return;
        }

        let connection = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
        connection.createAPIConnection()
            .on("connect", () => {
                globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished", true);
                globalObject.setData("descriptionAPI", "networkInteraction", "previousConnectionStatus", true);
            })
            .on("connectFailed", (err) => {
                writeLogFile("error", err.toString() + funcName);
            })
            .on("close", (msg) => {
                writeLogFile("info", msg.toString() + funcName);

                console.log("func 'connectionWithModuleNetworkInteraction'");
                console.log("EVENT: close");

                globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished", false);

                setTimeout((() => {
                    if (!globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                        connection.createAPIConnection();
                    }
                }), TIME_INTERVAL);
            })
            .on("error", (err) => {
                writeLogFile("error", err.toString() + funcName);

                globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished", false);

                console.log("func 'connectionWithModuleNetworkInteraction'");
                console.log("EVENT: error");

                setTimeout((() => {
                    if (!globalObject.setData("descriptionAPI", "networkInteraction", "connectionEstablished")) {
                        connection.createAPIConnection();
                    }
                }), TIME_INTERVAL);
            });
    };
    connectionWithModuleNetworkInteraction();

    //обработчик событий сторонних модулей через API
    routeSocketIo.modulesEventGenerator(socketIo);

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