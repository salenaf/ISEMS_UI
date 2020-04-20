"use strict";

const passport = require("passport");

const headerPage = require("./pages/elements/headerPage");
const writeLogFile = require("../libs/writeLogFile");
const usersSessionInformation = require("../libs/mongodb_requests/usersSessionInformation");
//const checkAccessRightsExecute = require("../libs/check/checkAccessRightsExecute");
const changeAdministratorPassword = require("../libs/changeAdministratorPassword");

//const processingManagementUsers = require("./pages/processing_http_request/processingManagementUsers");
//const processingManagementSources = require("./pages/processing_http_request/processingManagementSources");

/**
 * Модуль маршрутизации для запросов к HTTP серверу
 * 
 * @param {*} app 
 * @param {*} socketIo 
 */
module.exports = function(app, socketIo) {
    const pages = require("./pages");
    const listPages = {
        "/": pages.mainPage,
        "/auth": pages.authenticate,
    };

    const listCustomPages = {
        "/analysis_sip": {
            access: "menuSettings.analysis_sip.status",
            handler: pages.analysisSIP,
        },
        "/security_event_management": {
            access: "menuSettings.security_event_management.status",
            handler: pages.securityEventManagement,
        },
        "/network_interaction": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteraction,
        },
        /*        "/decode_tools": {
            access: "menuSettings.element_tools.submenu.decode_tools.status",
            handler: pages.toolsDecode,
        },
        "/search_tools": {
            access: "menuSettings.element_tools.submenu.search_tools.status",
            handler: pages.toolsSearch,
        },*/
        "/setting_users": {
            access: "menuSettings.element_settings.submenu.setting_users.status",
            handler: pages.managementUsers,
        },
        "/setting_groups": { 
            access: "menuSettings.element_settings.submenu.setting_groups.status",
            handler: pages.managementGroups,
        },
        "/setting_organizations_and_sources": {
            access: "menuSettings.element_settings.submenu.setting_organizations_and_sources.status",
            handler: pages.managementOrganizationsAndSources,
        },
        "/setting_ids_rules": {
            access: "menuSettings.element_settings.submenu.setting_ids_rules.status",
            handler: pages.managementIdsRules,
        },
        "/setting_search_rules": {
            access: "menuSettings.element_settings.submenu.setting_search_rules.status",
            handler: pages.managementSearchRules,
        },
        "/setting_geoip": {
            access: "menuSettings.element_settings.submenu.setting_geoip.status",
            handler: pages.managementGeoIp,
        },
        "/setting_reputational_lists": {
            access: "menuSettings.element_settings.submenu.setting_reputational_lists.status",
            handler: pages.managementReputationalLists,
        },
    };

    let funcName = " (route/index.js)";

    function isAuthenticated(req, res, next) {
        if (req.isAuthenticated()) next();
        else res.redirect("/auth");
    }

    app.route("/auth")
        .get((req, res) => {
            if (req.isAuthenticated()) pages.mainPage.call(null, req, res, socketIo);
            else listPages["/auth"].call(null, req, res);
        })
        .post(passport.authenticate("local", {
            successRedirect: "/",
            failureRedirect: "/auth?username=error"
        }));

    app.get("/", isAuthenticated, (req, res) => {       
        //добавляем идентификатор sessionID к сессионным данным о пользователе
        usersSessionInformation.setSessionID(req.session.passport.user, req.sessionID, (err) => {
            if (err) writeLogFile("error", err.toString());

            headerPage(req)
                .then((objHeader) => {
                    listPages["/"].call(null, req, res, objHeader);
                }).catch((err) => {
                    writeLogFile("error", err.toString());
                    res.render("500", {});
                });
        });
    });

    app.post("/change_password", isAuthenticated, (req, res) => {
        changeAdministratorPassword(req, (jsonObj) => {
            res.json(jsonObj).end();
        });
    });

    for(let pathPage in listCustomPages){
        app.get(pathPage, isAuthenticated, (req, res) => {
            headerPage(req)
                .then((objHeader) => {
                    try {
                        let listElem = listCustomPages[pathPage].access.split(".");
                        let isAccess = objHeader;
                        for(let i = 0; i < listElem.length; i++){
                            isAccess = isAccess[listElem[i]];
                        }

                        if (isAccess === "false") throw new Error("Access denied");

                        listCustomPages[pathPage].handler.call(null, req, res, objHeader);
                    } catch (err) {
                        res.render("403", {});
                    }
                }).catch((err) => {
                    console.log("===== route/index ERROR: 1 ======");
                    console.log(err);       

                    writeLogFile("error", err.toString()+funcName);
                    res.render("500", {});
                });
        });
    }

    //УПРАВЛЕНИЕ ИСТОЧНИКАМИ (Экспорт XML файла с настройками источников)
    /*app.get("/export_file_setup_hosts", isAuthenticated, (req, res) => {
        return processingDownloadFileSourceSetting(req, res);
    });*/

    //ВЫХОД
    app.get("/logout", (req, res) => {
        req.logOut();
        req.session.destroy();

        //удаляем сессионные данные о пользователе
        usersSessionInformation.delete(req.sessionID, (err) => {
            if (err) writeLogFile("error", err.toString()+funcName);
        });

        /**
         * Здесь нужно удалять информацию еще и из
         * globalObject
         * 
         */

        res.redirect("/auth");
    });

    if (process.env.NODE_ENV !== "development") {
        app.use(function(err, req, res) {

            console.log("===== route/index ERROR: 2 ======");
            console.log(err);

            res.render("500", {});
        });
    }
};