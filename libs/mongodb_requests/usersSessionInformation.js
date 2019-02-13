/*
 * Информация о пользователе связанная с идентификатором его сессии
 *
 * Версия 0.1, дата релиза 16.01.2019
 * */

'use strict';

const debug = require('debug')('usersSessionInformation');

const models = require('../../controllers/models');
const globalObject = require('../../configure/globalObject');
const mongodbQueryProcessor = require('../../middleware/mongodbQueryProcessor');

//создаем новую запись о сессии
module.exports.create = function(login, passportID, isDefault, cb) {

    debug('!!!! создаем новую запись о сессии !!!!');

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
                query: { group_name: userData.group }
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
                    group_settings: {
                        menu_items: objData.groupData.menu_items,
                        management_analysis_sip: objData.groupData.management_analysis_sip,
                        management_security_event_management: objData.groupData.management_security_event_management,
                        management_network_interaction: objData.groupData.management_network_interaction,
                        management_users: objData.groupData.management_users,
                        management_groups: objData.groupData.management_groups,
                        management_objects_and_subjects: objData.groupData.management_objects_and_subjects,
                        management_ids_rules: objData.groupData.management_ids_rules,
                        management_geoip: objData.groupData.management_geoip,
                        management_search_rules: objData.groupData.management_search_rules,
                        management_reputational_lists: objData.groupData.management_reputational_lists
                    },
                    isPasswordDefaultAdministrator: isDefault,
                    dateCreate: +(new Date())
                }
            }, err => {
                if (err) reject(err);
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

    debug('изменить параметр group_settings');

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

    debug('устанавливаем идетификатор сессии');
    debug(`passportID: ${passportID}`);
    debug(`sessionID: ${sessionID}`);

    globalObject.setData('users', sessionID, {});

    mongodbQueryProcessor.queryUpdate(
        models.modelSessionUserInformation, {
            query: { passport_id: passportID },
            update: { session_id: sessionID }
        }, err => {
            if (err) cb(err);
            else cb(null);
        }
    );
};

//получить всю информацию о пользователе по идентификаторам passportId или sessionId 
module.exports.getInformation = function(objID, cb) {

    debug('получить всю информацию о пользователе по идентификаторам passportId или sessionId');
    debug(objID);

    if (Object.keys(objID).length === 0) return cb(new Error('objId is empty'));

    let isExistPassportId = (typeof objID.passportId === 'undefined');
    let isExistSessionId = (typeof objID.sessionId === 'undefined');

    if (isExistPassportId && isExistSessionId) return cb(new Error('ID missing passportId or sessionID'));

    let obj = {
        'passportId': 'passport_id',
        'sessionId': 'session_id'
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

    debug('удаление всей информации о пользователе');

    mongodbQueryProcessor.queryDelete(models.modelSessionUserInformation, {
        query: {
            session_id: sessionID
        }
    }, err => {
        if (err) cb(err);
        else cb(null);
    });
};