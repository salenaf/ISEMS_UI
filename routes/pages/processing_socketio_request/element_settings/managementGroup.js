/**
 * Модуль обработки событий по управлению группами
 * 
 * Версия 0.1, дата релиза 14.02.2019
 */

'use strict';

const debug = require('debug')('managementGroup');

const models = require('../../../../controllers/models');
const createUniqID = require('../../../../libs/helpers/createUniqID');
const moongodbQueryProcessor = require('../../../../middleware/mongodbQueryProcessor');

/**
 * @param data объект типа { actionType: <тип_действия>, arguments: {<набор аргументов>} }
 * @param cb функция обратного вызова, вернет new Error() и 
 *      { isProcessed: true/false, messageError: <сообщение пользователю> }
 */
module.exports = function(data, cb) {
    let errMsg = 'the object being processed is not valid';
    let processing = {
        'create': createGroup,
        'edit': editGroup,
        'delete': deleteGroup
    };

    if (typeof data.arguments === 'undefined') {
        return cb(new Error(errMsg));
    }

    if ((typeof data.arguments.groupName === 'undefined') || (typeof processing[data.actionType] === 'undefinde')) {
        return cb(new Error(errMsg));
    }

    let groupName = data.arguments.groupName;

    if (!(/\b^[a-zA-Z0-9]+$\b/.test(groupName))) {
        return cb(null, {
            isProcessed: false,
            messageError: 'Получено некорректное имя группы'
        });
    }

    processing[data.actionType](data.arguments, err => {
        if (err) cb(err);
        else cb(null, {
            isProcessed: true,
            messageError: ''
        });
    });
};

function createGroup(data, callback) {

    debug('START func GROUP ADD');

    new Promise((resolve, reject) => {
        moongodbQueryProcessor.querySelect(models.modelGroup, {
            query: { group_name: 'administrator' },
            select: { _id: 0, __v: 0, date_register: 0, group_name: 0 }
        }, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    }).then(results => {
        let changeStatus = function(objData) {
            let { id, state, listElements, count } = objData;
            if (count > 10) return;

            if ((typeof listElements.id !== 'undefinde') && (typeof listElements.status === 'undefined')) {
                listElements.id = createUniqID.getMD5(data.groupName + listElements.id);
            }

            for (let item in listElements) {
                if (typeof listElements[item] !== 'object') continue;
                if (typeof listElements[item].id === 'undefinde') continue;

                let actualID = listElements[item].id;
                if (actualID !== id) {
                    changeStatus({
                        id: id,
                        state: state,
                        listElements: listElements[item],
                        count: ++count
                    });

                    continue;
                }

                listElements[item].status = state;
                listElements[item].id = createUniqID.getMD5(data.groupName + actualID);
            }
        }


        let listElements = results.toObject();
        for (let hex in data.listPossibleActions) {
            for (let key in listElements) {
                if (key === 'id') continue;

                changeStatus({
                    id: hex,
                    state: data.listPossibleActions[hex],
                    listElements: listElements[key],
                    count: 0
                });
            }
        }

        listElements = Object.assign(listElements, {
            group_name: data.groupName,
            date_register: +(new Date())
        });

        return listElements
    }).then(newList => {
        return new Promise((resolve, reject) => {
            moongodbQueryProcessor.queryCreate(models.modelGroup, { document: newList }, err => {
                if (err) reject(err);
                else resolve();
            });
        });
    }).then(() => {
        callback(null);
    }).catch(err => {
        callback(err);
    });
}

function editGroup(data, callback) {

}

function deleteGroup(data, callback) {

}