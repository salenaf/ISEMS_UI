/*
 * Информация о пользователе связанная с идентификатором его сессии
 *
 * Версия 0.1, дата релиза 16.01.2019
 * */

"use strict";

const debug = require("debug")("usersSessionInformation");

const models = require("../../controllers/models");
const globalObject = require("../../configure/globalObject");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

//создаем новую запись о сессии
module.exports.create = function(login, passportID, isDefault, cb) {

    debug("!!!! создаем новую запись о сессии !!!!");

    new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelUser, {
            query: { login: login }
        }, (err, doc) => {
            if (err) reject(err);
            else resolve(doc);
        });
    }).then(userData => {
        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.querySelect(models.modelGroup, {
                query: { group_name: userData.group },
                select: { _id: 0, __v: 0, date_register: 0, group_name: 0 }
            }, (err, doc) => {
                if (err) reject(err);
                else resolve({ userData: userData, groupData: doc });
            });
        });
    }).then(objData => {
        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.queryCreate(models.modelSessionUserInformation, {
                document: {
                    passport_id: passportID,
                    login: objData.userData.login,
                    user_name: objData.userData.user_name,
                    user_settings: {
                        sourceMainPage: objData.userData.settings.sourceMainPage
                    },
                    group_name: objData.userData.group,
                    group_settings: objData.groupData,
                    isPasswordDefaultAdministrator: isDefault,
                    dateCreate: +(new Date())
                }
            }, err => {
                if (err) {
                    console.log(err);

                    reject(err);
                }
                else resolve(null);
            });
        });
    }).then(() => {
        cb(null);
    }).catch(err => {
        cb(err);
    });
};

//изменить параметр group_settings
module.exports.changeGroupSettings = function(groupName, obj, cb) {

    debug("изменить параметр group_settings");

    mongodbQueryProcessor.queryUpdate(
        models.modelSessionUserInformation, {
            query: { group_name: groupName },
            update: { group_settings: obj }
        }, err => {
            if (err) cb(err);
            else cb(null);
        }
    );
};

//устанавливаем идетификатор сессии
module.exports.setSessionID = function(passportID, sessionID, cb) {

    debug("устанавливаем идетификатор сессии");
    debug(`passportID: ${passportID}`);
    debug(`sessionID: ${sessionID}`);

    globalObject.setData("users", sessionID, {});
    new Promise((resolve, reject) => {

        debug("query update");

        mongodbQueryProcessor.queryUpdate(
            models.modelSessionUserInformation, {
                query: { passport_id: passportID },
                update: { session_id: sessionID }
            }, err => {
                if (err) reject(err);
                else resolve();
            }
        );
    }).then(() => {
        return new Promise((resolve, reject) => {

            debug("query select");

            mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, { query: { session_id: sessionID } }, (err, session) => {
                if (err) return reject(err);

                resolve({
                    userLogin: session.login,
                    userName: session.user_name,
                    userGroup: session.group_name,
                    groupSettings: session.group_settings,
                    userSettings: session.user_settings,
                });
            });


            /**
             * return new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, { isMany: true }, (err, sessions) => {
            if (err) reject(err);

            let listSession = {};

            sessions.forEach(element => {
                listSession[element.session_id] = {
                    userLogin: element.login,
                    userName: element.user_name,
                    userGroup: element.group_name,
                    groupSettings: element.group_settings,
                    userSettings: element.user_settings,
                };
            });

            resolve(listSession);
        });
    });
             * 
             */
        });
    }).then((userSession) => {
        debug("------------------------");
        debug(userSession);
        debug("------------------------");

        debug("Добавляем данные в глобальный объект 'globalObject'");

        let isTrue = globalObject.setData("users", sessionID, userSession);
        debug(`Write data is success: '${isTrue}'`);


        debug("Проверяем записанные данные");
        debug(globalObject.getData("users", userSession.sessionId));

        cb(null);
    }).catch((err) => {
        cb(err);
    });
};

//получить всю информацию о пользователе по идентификаторам passportId или sessionId 
module.exports.getInformation = function(objID, cb) {

    debug("получить всю информацию о пользователе по идентификаторам passportId или sessionId");
    debug(objID);

    if (Object.keys(objID).length === 0) return cb(new Error("objId is empty"));

    let isExistPassportId = (typeof objID.passportId === "undefined");
    let isExistSessionId = (typeof objID.sessionId === "undefined");

    if (isExistPassportId && isExistSessionId) return cb(new Error("ID missing passportId or sessionID"));

    let obj = {
        "passportId": "passport_id",
        "sessionId": "session_id"
    };

    let objQuery = {};
    for (let key in objID) {
        objQuery[obj[key]] = objID[key];
    }

    mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, { query: objQuery }, (err, result) => {
        if (err) cb(err);
        else cb(null, result);
    });
};

//удаление всей информации о пользователе
module.exports.delete = function(sessionID, cb) {

    debug("удаление всей информации о пользователе");

    new Promise((resolve, reject) => {
        mongodbQueryProcessor.queryDelete(models.modelSessionUserInformation, { query: { session_id: sessionID } }, err => {
            if (err) reject(err);
            else resolve(null);
        });
    }).then(() => {
        globalObject.deleteData("users", sessionID);

        cb(null);
    }).catch(err => {
        cb(err);
    });
};