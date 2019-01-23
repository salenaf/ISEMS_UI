/*
 * Управление пользовательскими настройками
 *
 * - управление дачбордами на главной странице (добавление, удаление, изменение порядка расположения)
 *
 * Версия 0.1, дата релиза 19.05.2017
 * */

'use strict';

const async = require('async');

const models = require('../../controllers/models');
const getSessionId = require('../helpers/getSessionId');
const writeLogFile = require('../writeLogFile');

//добавление нового идентификатора источника в коллекцию 'session.user.informations'
module.exports.addNewDashboardSource = function(socketIo, data) {
    getSessionId('socketIo', socketIo, (err, sessionId) => {
        if (err) return writeLogFile('error', err.toString());

        async.series([
            //проверяем пользовательские данные
            function(callback) {
                checkUserData('addSourceDashboard', data.sourceId, (err) => {
                    if (err) callback(err);
                    else callback(null);
                });
            },
            //проверяем наличие идентификатора источника в массиве источников раздела настроек пользователя
            function(callback) {
                models.modelSessionUserInformation.findOne({ session_id: sessionId, 'user_settings.sourceMainPage': +data.sourceId }, { _id: 1 },
                    function(err, document) {
                        if (err) return callback(err);

                        if (document === null) callback(null);
                        else callback(new Error('source ID \'' + data.sourceId + '\' already exists'));
                    });
            }
        ], function(err) {
            if (err) return writeLogFile('error', err.toString());

            //добавляем идентификатор источника в коллекцию session.user.informations
            models.modelSessionUserInformation.update({ session_id: sessionId }, {
                '$push': { 'user_settings.sourceMainPage': +data.sourceId }
            }, function(err) {
                if (err) writeLogFile('error', err.toString());
            });
        });
    });
};

//иззменение идентификатора источника в коллекцию 'users'
module.exports.changeCollectionUsersUserSettings = function(type, socketIo, data) {
    getSessionId('socketIo', socketIo, (err, sessionId) => {
        if (err) return writeLogFile('error', err.toString());

        models.modelSessionUserInformation.findOne({ session_id: sessionId }, { _id: 1, login: 1 },
            function(err, document) {
                if (err) return writeLogFile('error', err.toString());
                if ((document === null) || (typeof document.login === 'undefined')) return writeLogFile('error', 'you cannot change a source identifier, cannot determine the username of the user');

                if (type === 'add') {
                    models.modelUser.update({ login: document.login }, {
                        '$addToSet': { 'settings.sourceMainPage': +data.sourceId }
                    }, function(err) {
                        if (err) writeLogFile('error', err.toString());
                    });
                }
                if (type === 'delete') {
                    models.modelUser.update({ login: document.login }, {
                        '$pull': { 'settings.sourceMainPage': +data.sourceId }
                    }, function(err) {
                        if (err) writeLogFile('error', err.toString());
                    });
                }
            });
    });
};

//удаление идентификатора источника из раздела настроек пользователя
module.exports.deleteDashboardSource = function(socketIo, data) {
    getSessionId('socketIo', socketIo, (err, sessionId) => {
        if (err) return writeLogFile('error', err.toString());

        checkUserData('addSourceDashboard', data.sourceId, (err) => {
            if (err) writeLogFile('error', err.toString());

            models.modelSessionUserInformation.update({ session_id: sessionId }, {
                '$pull': { 'user_settings.sourceMainPage': +data.sourceId }
            }, function(err) {
                if (err) writeLogFile('error', err.toString());
            });
        });
    });
};

//проверка пользовательских данных
function checkUserData(type, data, func) {
    //типы данных
    let objType = {
        sourceId: 'integer'
    };
    //шаблоны
    let objPattern = {
        integer: new RegExp('^[0-9]+$')
    };
    let objProcess = {
        addSourceDashboard: function() {
            if (objPattern[objType['sourceId']].test(+data)) func(null);
            else func(new Error('the identifier \'sourceId\' is not a numeric value'));
        }
    };

    objProcess[type]();
}