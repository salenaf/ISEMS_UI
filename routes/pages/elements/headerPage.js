/*
 * Модуль формирующий информацию для заголовка страницы
 *
 * Версия 0.1, дата релиза 15.01.2019
 * */

"use strict";

const globalObject = require("../../../configure/globalObject");
const usersSessionInformation = require("../../../libs/mongodb_requests/usersSessionInformation");

module.exports = function(req) {

    //    console.log("func 'headerPage', START...");
    //    console.log(req.session);

    return new Promise((resolve, reject) => {
        usersSessionInformation.getInformation(req, (err, result) => {
            if (err) reject(err);
            else resolve(result);
        });
    }).then((result) => {
        let objMenuSettings = {};

        //        console.log("==== func 'headerPage' ====");
        //        console.log(result);
        //        console.log("===========================");

        let menuItems = result.group_settings.menu_items;

        let createList = function(listMenu, items) {
            for (let key in items) {
                if (typeof items[key].name === "undefined") {
                    if (items[key].status) {
                        listMenu[key] = { name: items[key].description, status: items[key].status };
                    }

                    continue;
                }

                listMenu[key] = { name: items[key].name, submenu: {} };

                createList(listMenu[key].submenu, items[key]);
            }
        };

        createList(objMenuSettings, menuItems);

        return {
            login: result.login,
            userName: result.user_name,
            isPasswordDefaultAdministrator: result.isPasswordDefaultAdministrator,
            connectionModules: {
                moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
            },
            menuSettings: objMenuSettings
        };
    }).catch((err) => {
        throw (err);
    });
};