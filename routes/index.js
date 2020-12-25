"use strict";

const passport = require("passport");

const pages = require("./pages");
const headerPage = require("./pages/elements/headerPage");
const writeLogFile = require("../libs/writeLogFile");
const usersSessionInformation = require("../libs/mongodb_requests/usersSessionInformation");
const changeAdministratorPassword = require("../libs/changeAdministratorPassword");

/**
 * Модуль маршрутизации для запросов к HTTP серверу
 * 
 * @param {*} app 
 */
module.exports = function(app) {
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
        "/network_interaction_page_file_download": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteractionPageFileDownload,
        },
        "/network_interaction_page_search_tasks": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteractionPageSearchTasks,
        },
        "/network_interaction_page_statistics_and_analytics": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteractionPageStatisticsAndAnalytics,
        },
        "/network_interaction_page_statistics_and_analytics_detal_task": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteractionpageStatisticsAndAnalyticsDetalTask,
        },
        "/network_interaction_page_source_telemetry": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteractionPageTelemetry,
        },
        "/network_interaction_page_notification_log": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteractionPageNotificationLog,
        },
        "/network_interaction_page_template_log": {
            access: "menuSettings.network_interaction.status",
            handler: pages.networkInteractionPageTemplateLog,
        },
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
        // "/setting_search_rules": {
        //     access: "menuSettings.element_settings.submenu.setting_search_rules.status",
        //     handler: pages.managementIdsRules,//managementSearchRules,
        // },
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
            if (req.isAuthenticated()) {
                headerPage(req)
                    .catch((err) => {
                        writeLogFile("error", err.toString());
                        res.render("500", {});
                    });
            } else {
                res.render("auth", {});
            }
        })
        .post(passport.authenticate("local", {
            successRedirect: "/",
            failureRedirect: "/auth?username=error"
        }));

    app.get("/", isAuthenticated, (req, res) => {
        //добавляем информацию о пользователе (passport id) в sessions_user_information
        usersSessionInformation.create(req.session.passport.user, req.sessionID, (err) => {
            if (err) writeLogFile("error", err.toString());

            headerPage(req)
                .then((objHeader) => {

                    /**
                     * потом для главной странице обработчик в
                     * routes/pages/mainPage.js
                     */

                    res.render("index", { header: objHeader });
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

    for (let pathPage in listCustomPages) {
        app.get(pathPage, isAuthenticated, (req, res) => {
            headerPage(req)
                .then((objHeader) => {
                    try {
                        let listElem = listCustomPages[pathPage].access.split(".");
                        let isAccess = objHeader;
                        for (let i = 0; i < listElem.length; i++) {
                            isAccess = isAccess[listElem[i]];
                        }

                        if (isAccess === "false") throw new Error("Access denied");

                        listCustomPages[pathPage].handler.call(null, req, res, objHeader);
                    } catch (err) {
                        res.render("403", {});
                    }
                }).catch((err) => {
                    writeLogFile("error", err.toString() + funcName);
                    res.render("500", {});
                });
        });
    }

    //ВЫХОД
    app.get("/logout", (req, res) => {
        new Promise((resolve, reject) => {
            usersSessionInformation.delete(req.sessionID, (err) => {
                if (err) reject(err);
                else resolve(null);
            });
        }).then(() => {
            return new Promise((resolve, reject) => {
                require("../libs/mongodb_requests/passportAdditionInformation").delete(req.session.passport.user, (err) => {
                    if (err) reject(err);
                    else resolve(null);
                });
            });
        }).then(() => {
            req.logOut();
            req.session.destroy();

            res.redirect("/auth");
        }).catch((err) => {
            writeLogFile("error", err.toString() + funcName);
        });
    });

    if (process.env.NODE_ENV !== "development") {
        app.use((err, req, res) => {
            res.render("500", {});
        });
    }
};