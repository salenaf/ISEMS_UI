/*
* Удаление части или всех решающих правил СОА
*
* Версия 0.1, дата релиза 17.08.2017
* */

'use strict';

const models = require('../../../controllers/models/index');
const getSessionId = require('../../helpers/getSessionId');

module.exports = function (actionType, settings, socketIo, func) {
    getSessionId('socketIo', socketIo, function (err, sessionId) {
        if(err) return func(err);

        models.modelSessionUserInformation.findOne(
            { session_id: sessionId },
            { _id: 0, login: 1, user_name: 1 },
            function (err, objUserSettings) {
                if(err) return func(err);

                if(actionType === 'drop data base'){
                    removeAllIdsRules(objUserSettings, (err) => {
                        if(err) func(err);
                        else func(null);
                    });
                } else if(actionType === 'drop change class'){
                    removeChangeIdsRules(objUserSettings, settings, (err) => {
                        if(err) func(err);
                        else func(null);
                    });
                } else {
                    func(new Error('unspecified type of action'));
                }
            });
    });
};

//удаление всего содержимого коллекции решающих правил СОА
function removeAllIdsRules (objUserSettings, callback) {
    new Promise((resolve, reject) => {
        models.modelRulesIDS.remove((err) => {
            if(err) reject(err);
            else resolve(null);
        });
    })
        .then(() => {
            return new Promise((resolve, reject) => {
                models.modelAdditionalInformation.update({ ids_rules: {
                    create_date : +new Date,
                    create_login : objUserSettings.login,
                    create_username : objUserSettings.user_name,
                    count_rules : 0
                }}, (err) => {
                    if(err) reject(err);
                    else resolve(null);
                });
            });
        })
        .then(() => {
            callback(null);
        })
        .catch((reject) => {
            callback(reject);
        });
}

//удаление выбранных классов из коллекции решающих правил СОА
function removeChangeIdsRules (objUserSettings, settings, callback) {
    let checkArrayRemoveClassType = checkClassType(settings.arrayChangeClass);
    if(checkArrayRemoveClassType.length === 0) return callback(new Error('incorrect value \'classType\''));

    new Promise((resolve, reject) => {
        models.modelRulesIDS.remove({ classType: { '$in': checkArrayRemoveClassType }},(err) => {
            if(err) reject(err);
            else resolve(null);
        });
    })
        .then(() => {
            return new Promise((resolve, reject) => {
                models.modelRulesIDS.count({}, (err, countRules) => {
                    if(err) reject(err);

                    models.modelAdditionalInformation.update({ ids_rules: {
                        create_date : +new Date,
                        create_login : objUserSettings.login,
                        create_username : objUserSettings.user_name,
                        count_rules : countRules
                    }}, (err) => {
                        if(err) reject(err);
                        else resolve(null);
                    });
                });
            });
        })
        .then(() => {
            callback(null);
        })
        .catch((reject) => {
            callback(reject);
        });
}

//проверяем перечень классов решающих правил которые требуется удалить
function checkClassType (arrayClassType) {
    return arrayClassType.filter((item) => /[\w-]+/.test(item));
}