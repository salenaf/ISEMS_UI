/*
 * Настройка express
 *
 * Версия 0.1, дата релиза 14.01.2019
 * */

"use strict";

module.exports = function(app, express, io) {
    const ss = require("socket.io-stream");
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
    const routeSocketIo = require("../routes/routeSocketIo");
    const AuthenticateStrategy = require("./authenticateStrategy");

    //срок окончания хранения постоянных cookie 14 суток
    let expiresDate = new Date(Date.now() + ((60 * 60 * 24 * 14) * 1000));

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
        routeSocketIo.eventHandling(socket);

        /* upload file */
        //routeSocketIo.uploadFiles(socket, ss);
    });

    /*
     * Public directory
     * */
    app.use(express.static(path.join(__dirname, "../public")));
    app.use("/public", express.static(path.join(__dirname, "../public")));

    /*
     * Routing
     * */
    routes(app, socketIo);

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