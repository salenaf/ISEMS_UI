"use strict";

const async = require("async");

const models = require("../../../controllers/models");
const globalObject = require("../../../configure/globalObject");
const usersSessionInformation = require("../../../libs/mongodb_requests/usersSessionInformation");

/**
 * Модуль формирующий информацию для заголовка страницы
 * 
 * @param{*} req
 */
module.exports = function(req) {

    console.log("func 'headerPage', START...");
    console.log(req.session.passport.user);

    return new Promise((resolve, reject) => {
        async.parallel({
            getPasswordInfo: (callback) => {

                console.log(`search info password from passwordID ${req.session.passport.user}`);

                require("../../../middleware/mongodbQueryProcessor").querySelect(models.modelAdditionalPassportInformation, {
                    query: { passport_id: req.session.passport.user }
                }, (err, result) => {
                    if (err) callback(err);
                    else callback(null, result);
                });
            },
            getSessionInfo: (callback) => {
                //получаем общую информацию о пользователе по его сессии
                usersSessionInformation.getInformation(req, (err, result) => {
                    if (err) callback(err);
                    else callback(null, result);
                });
            },
        }, (err, result) => {
            if(err) reject(err);
    
            let objMenuSettings = {};
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
            
            console.log("==== func 'headerPage' ====");
            console.log(result);
            console.log("===========================");

            try {
                let menuItems = result.getSessionInfo.group_settings.menu_items;
                createList(objMenuSettings, menuItems);
        
                resolve({
                    login: result.getSessionInfo.login,
                    userName: result.getSessionInfo.user_name,
                    isPasswordDefaultAdministrator: result.getPasswordInfo.is_admin_password_default,
                    connectionModules: {
                        moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
                    },
                    menuSettings: objMenuSettings
                });
            } catch(err){
                resolve({
                    login: "",
                    userName: "",
                    isPasswordDefaultAdministrator: false,
                    connectionModules: {
                        moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
                    },
                    menuSettings: {}
                });                
            }
        });
    });

/*
    return new Promise((resolve, reject) => {
        //получаем общую информацию о пользователе по его сессии
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
    });*/
};