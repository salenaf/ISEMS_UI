"use strict";

const url = require("url");
const async = require("async");

const globalObject = require("../../../configure/globalObject");
const writeLogFile = require("../../../libs/writeLogFile");
const checkAccessRightsPage = require("../../../libs/check/checkAccessRightsPage");

/**
 * Модуль формирующий страницу статистики и аналитики
 * 
 * @param {*} req
 * @param {*} res
 * @param {*} objHeader
 */
module.exports = function(req, res, objHeader) {
    async.parallel({
        permissions: (callback) => {
            checkAccessRightsPage(req, (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        mainInformation: (callback) => {

            callback(null, {});

        },
        widgetsInformation: (callback) => {
            let numConnect = 0,
                numDisconnect = 0;

            let listSources = globalObject.getData("sources");
            for (let source in listSources) {
                if (listSources[source].connectStatus) {
                    numConnect++;
                } else {
                    numDisconnect++;
                }
            }

            callback(null, {
                numConnect: numConnect,
                numDisconnect: numDisconnect,
            });
        }
    }, (err, result) => {
        if (err) {
            writeLogFile("error", err.toString());
            res.render("menu/network_interaction", {
                header: objHeader,
                userPermissions: {},
                mainInformation: {},
            });

            return;
        }

        let userPermissions = result.permissions.group_settings;
        let readStatus = userPermissions.menu_items.network_interaction.status;

        if (readStatus === false) return res.render("403");

        console.log("func 'networkInteraction' PAGE STATISTICS AND ANALYTICS DETAL TASK");
        console.log(url.parse(req.originalUrl).query);
        /**
         * Здесь нужно получить ID задачи из URL и отправить на страницу,
         * что бы потом со страницы сделать запрос через backend ISEMS-UI к ISEMS-NIH_master
         * 
         * (кстати можно еще какие нибудь параметры получить через URL,
         * что бы вывести первичную информацию, например ID и названия источника и т.д.)
         */

        //console.log(result.widgetsInformation);

        res.render("menu/network_interaction/page_statistics_and_analytics_detal_task", {
            header: objHeader,
            listItems: {
                connectionModules: {
                    moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
                },
                userPermissions: userPermissions.management_network_interaction.element_settings,
                mainInformation: result.mainInformation,
                widgetsInformation: result.widgetsInformation,
                listSources: globalObject.getData("sources"),
            },
        });
    });
};