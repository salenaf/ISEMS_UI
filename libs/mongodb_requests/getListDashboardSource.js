/*
* Получаем список источников для главной страницы выбранного пользователя
*
* Версия 0.1, дата релиза 23.05.2017
* */

'use strict';

const models = require('../../controllers/models');
const writeLogFile = require('../writeLogFile');

module.exports = function (req, func) {
    try {
        let errorMessage = 'not found info by a session ID';
        if(!(~req.headers.cookie.indexOf(' '))){
            writeLogFile('error', new Error(errorMessage));
            return func(new Error(errorMessage));
        }

        let arrayId = req.headers.cookie.split(' ');
        let sessionId = '';
        for(let i = 0; i < arrayId.length; i++){
            if(~arrayId[i].indexOf('connect.sid')){
                let session = arrayId[i].split('=')[1];
                sessionId = session.split('.')[0].substr(4);
                break;
            }
        }

        if(sessionId.length === 0){
            writeLogFile('error', new Error(errorMessage));
            return func(new Error(errorMessage));
        }

        models.modelSessionUserInformation.findOne({ 'session_id': sessionId }, { _id: 0, user_settings: 1 }, (err, document) => {
            if(err) return func(err);
            if(document === null) return func(new Error(errorMessage));

            func(null, document.user_settings.sourceMainPage);
        });
    } catch (err) {
        func(err);
    }
};