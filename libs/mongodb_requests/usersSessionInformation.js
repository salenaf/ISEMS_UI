/*
 * Информация о пользователе связанная с идентификатором его сессии
 *
 * Версия 0.2, дата релиза 20.04.2020
 * */

"use strict";

const debug = require("debug")("usersSessionInformation");

const models = require("../../controllers/models");
const globalObject = require("../../configure/globalObject");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

/**
 * создаем новую запись о сессии
 * 
 * @param {*} login
 * @param {*} passportID
 * @param {*} isDefault
 * @param {*} callback
 */
module.exports.create = function(login, passportID, isDefault, callback) {

    debug("!!!! создаем новую запись о сессии !!!!");

    new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, {
            query: { passport_id: passportID }
        }, (err, doc) => {
            if (err) reject(err);
            else resolve(doc);
        });
    }).then((sessionInfo) => {
        //проверяем наличие информации о пользователе
        if(sessionInfo !== null){
            return callback(null);
        }

        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.querySelect(models.modelUser, {
                query: { login: login }
            }, (err, doc) => {
                if (err) reject(err);
                else resolve(doc);
            });
        }).then((userData) => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelGroup, {
                    query: { group_name: userData.group },
                    select: { _id: 0, __v: 0, date_register: 0, group_name: 0 }
                }, (err, doc) => {
                    if (err) reject(err);
                    else resolve({ userData: userData, groupData: doc });
                });
            });
        }).then((objData) => {
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
                }, (err) => {
                    if (err) reject(err);
                    else resolve(null);
                });
            });
        }).then(() => {
            callback(null);
        });
    }).catch((err) => {
        callback(err);
    });
};

/**
 * изменить параметр group_settings
 * 
 * @param {*} groupName
 * @param {*} obj
 * @param {*} callback
 */
module.exports.changeGroupSettings = function(groupName, obj, callback) {

    debug("изменить параметр group_settings");

    mongodbQueryProcessor.queryUpdate(
        models.modelSessionUserInformation, {
            query: { group_name: groupName },
            update: { group_settings: obj }
        }, (err) => {
            if (err) callback(err);
            else callback(null);
        }
    );
};

/**
 * добавляем данные о группе пользователя в globalObject
 * 
 * @param {*} passportId
 * @param {*} sessionId
 * @param {*} callback
 */
module.exports.setSessionID = function(passportId, sessionId, callback) {

    debug("устанавливаем идетификатор сессии");
    debug(`passportID: ${passportId}`);
    debug(`sessionID: ${sessionId}`);

    new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, 
            { query: { passport_id: passportId, } }, 
            (err, session) => {
                if (err) reject(err);
                else resolve({
                    userLogin: session.login,
                    userName: session.user_name,
                    userGroup: session.group_name,
                    groupSettings: session.group_settings,
                    userSettings: session.user_settings,
                });
            });
    }).then((userSession) => {
        debug("Добавляем данные в глобальный объект 'globalObject'");

        let isTrue = globalObject.setData("users", sessionId, userSession);
        debug(`Write data is success: '${isTrue}'`);


        debug("Проверяем записанные данные");
        debug(globalObject.getData("users", userSession.sessionId));

        callback(null);
    }).catch((err) => {
        callback(err);
    });
};

/**
 * получить всю информацию о пользователе по идентификаторам passportId или sessionId 
 *
 * @param {*} req
 * @param {*} callback
 */
module.exports.getInformation = function(req, callback) {

    debug("получить всю информацию о пользователе по идентификаторам passportId или sessionId");
    debug(`passport ID: ${req.user}`);

    try {
        let passportId = req.user;

        mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, 
            { query: { passport_id: passportId,}}, 
            (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
    } catch (err) {
        callback(err);
    }
};

/**
 * удаление всей информации о пользователе
 * 
 * @param {*} sessionId
 * @param {*} callback
 */
module.exports.delete = function(sessionId, callback) {

    debug("удаление всей информации о пользователе");

    new Promise((resolve, reject) => {
        mongodbQueryProcessor.queryDelete(models.modelSessionUserInformation, 
            { query: { session_id: sessionId } }, 
            (err) => {
                if (err) reject(err);
                else resolve(null);
            });
    }).then(() => {
        globalObject.deleteData("users", sessionId);

        callback(null);
    }).catch((err) => {
        callback(err);
    });
};