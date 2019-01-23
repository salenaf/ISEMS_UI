/*
 * Проверка авторизации пользователя
 *
 * Версия 0.1, дата релиза 11.05.2017
 * */

'use strict';

const models = require('../../controllers/models');
const getSessionId = require('../helpers/getSessionId');

module.exports = function(socketIo, callback) {
    getSessionId('socketIo', socketIo, (err, sessionId) => {
        models.modelSessionUserInformation.findOne({ session_id: sessionId }, { _id: 1 }, function(err, document) {
            if (err) return callback(err);

            if (document === null) callback(null, false);
            else callback(null, true);
        });
    });
};