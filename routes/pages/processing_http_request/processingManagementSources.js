/*
 * Обработка HTTP запросов по работе с источниками
 *
 * Версия 0.1, дата релиза 13.04.2017
 * */

'use strict';

const async = require('async');

const models = require('../../../controllers/models');
const objGlobals = require('../../../configure/globalObject');
const writeLogFile = require('../../../libs/writeLogFile');
const routeSocketIo = require('../../../routes/routeSocketIo');

module.exports = function(req, res, io, func) {
    let objData = req.body;

    if (!(/\b^[a-zA-Z0-9]+$\b/.test(objData.settings.hostId))) {
        writeLogFile('error', 'incorrect group name');
        return func({ type: 'danger', message: 'некорректный идентификатор источника', action: '' });
    }

    //просмотр информациие
    if (objData.actionType === 'read') {
        return showSourceInfo(objData.settings.hostId, function(err, document) {
            if (err) {
                writeLogFile('error', err.toString());
                func({ type: 'danger', message: 'внутренняя ошибка сервера', action: '' });
            } else {
                func({ sourceInformation: document, type: objData.settings.type });
            }
        });
    }

    //удаление информации
    if (objData.actionType === 'delete') {
        return deleteSource(objData.settings.hostId, req.sessionID, function(err, message) {
            if (err) {
                writeLogFile('error', err.toString());
                func({ type: 'danger', message: 'внутренняя ошибка сервера', action: '' });
            } else {
                //генерируем событие информирующее о изменении статуса источников
                routeSocketIo.eventEmitter(io, { type: 'changingStatusSource' });

                func(message);
            }
        });
    }

    let managementSource = new ManagementSource(objData);

    if (objData.actionType === 'create') {
        managementSource.createSources(function(err, message) {
            if (err) {
                writeLogFile('error', err.toString());
                func({ type: 'danger', message: 'внутренняя ошибка сервера', action: '' });
            } else {
                //генерируем событие информирующее о изменении статуса источников
                routeSocketIo.eventEmitter(io, { type: 'changingStatusSource' });

                func(message);
            }
        });
    }
    if (objData.actionType === 'edit') {
        managementSource.editSources(function(err, message) {
            if (err) {
                writeLogFile('error', err.toString());
                func({ type: 'danger', message: 'внутренняя ошибка сервера', action: '' });
            } else {
                //генерируем событие информирующее о изменении статуса источников
                routeSocketIo.eventEmitter(io, { type: 'changingStatusSource' });

                func(message);
            }
        });
    }

};

class ManagementSource {
    constructor(objData) {
        this.obj = objData;

        this.settingName = {
            hostId: 'int',
            shortNameHost: 'stringEnInt',
            fullNameHost: 'stringRuEnInt',
            ipaddress: 'ipaddressString',
            intervalReceiving: 'int'
        };

        this.regexpPattern = {
            int: new RegExp('^[0-9]{1,7}$'),
            stringEnInt: new RegExp('^[a-zA-Z0-9_\\-\\s]{3,15}$'),
            stringToken: new RegExp('^[a-zA-Z0-9\\s]+$'),
            stringRuEnInt: new RegExp('^[a-zA-Zа-яА-Яё0-9_\\-\\s\\.,]+$'),
            ipaddressString: new RegExp('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$'),
            network: new RegExp('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[/][0-9]{1,2}$')
        };
    }

    //валидация входных параметров
    checkUserData() {
        let newObject = {};

        try {
            for (let key in this.obj.settings) {
                if (key === 'rangeIpNetwork') continue;
                if (key === 'type') continue;

                let isExist = (typeof this.obj.settings[key] !== 'undefined');
                let pattern = this.regexpPattern[this.settingName[key]];

                if (isExist && (pattern.test(this.obj.settings[key]))) {
                    newObject[key] = this.obj.settings[key];
                }
            }

            if (!Array.isArray(this.obj.settings.rangeIpNetwork)) throw new Error('rangeIpNetwork is not Array');

            let newArrayIPNetwork = this.obj.settings.rangeIpNetwork.filter((item) => {
                if (~item.indexOf('/')) {
                    let [, mask] = item.split('/');
                    if (+mask > 32) return false;

                    return this.regexpPattern.network.test(item);
                } else {
                    return this.regexpPattern.ipaddressString.test(item);
                }
            });

            if (newArrayIPNetwork.length === 0) throw new Error('received incorrect ip addresses or networks');

            newObject.rangeIpNetwork = newArrayIPNetwork;

            if (Object.keys(newObject).length < 6) return {};
            else return newObject;
        } catch (err) {
            writeLogFile('error', err.toString());
            return {};
        }

    }

    //создание источника
    createSources(func) {
        let validObj = this.checkUserData();
        if (Object.keys(validObj).length === 0) return func(null, { type: 'danger', message: 'получены некорректные данные', action: '' });

        models.modelSource.findOne({ id: +validObj.hostId }, { id: 1, _id: 0 }, function(err, hostId) {
            if (err) return func(err);
            if (hostId !== null) return func(null, { type: 'warning', message: 'источник с идентификатором \'' + validObj.hostId + '\' уже существует', action: '' });

            models.modelSource.collection.insert({
                'date_register': +(new Date()),
                'date_change': +(new Date()),
                'id': +validObj.hostId,
                'short_name': validObj.shortNameHost,
                'detailed_description': validObj.fullNameHost,
                'ipaddress': validObj.ipaddress,
                'update_frequency': validObj.intervalReceiving,
                'range_monitored_addresses': validObj.rangeIpNetwork
            }, function(err) {
                if (err) return func(err);

                objGlobals.sources.sourceAvailability[+validObj.hostId] = {
                    shortName: validObj.shortNameHost,
                    detailedDescription: validObj.fullNameHost,
                    updateFrequency: validObj.intervalReceiving,
                    dateLastUpdate: null,
                    statusOld: false,
                    statusNew: false
                };

                func(null, { type: 'success', message: 'источник успешно добавлен', action: 'reload' });
            });
        });
    }

    //редактирование информации об источнике
    editSources(func) {
        let validObj = this.checkUserData();

        models.modelSource.findOneAndUpdate({ id: +validObj.hostId }, {
            'date_change': +(new Date()),
            'short_name': validObj.shortNameHost,
            'detailed_description': validObj.fullNameHost,
            'ipaddress': validObj.ipaddress,
            'update_frequency': validObj.intervalReceiving,
            'range_monitored_addresses': validObj.rangeIpNetwork
        }, function(err) {
            if (err) return func(err);

            objGlobals.sources.sourceAvailability[+validObj.hostId].shortName = validObj.shortNameHost;
            objGlobals.sources.sourceAvailability[+validObj.hostId].detailedDescription = validObj.fullNameHost;
            objGlobals.sources.sourceAvailability[+validObj.hostId].updateFrequency = validObj.intervalReceiving;
            objGlobals.sources.sourceAvailability[+validObj.hostId].dateLastUpdate = +new Date;

            func(null, { type: 'success', message: 'информация о источнике успешно изменена', action: 'reload' });
        });
    }
}

//просмотр информации
function showSourceInfo(sourceId, func) {
    models.modelSource.findOne({ 'id': +sourceId }, { _id: 0 }, function(err, document) {
        if (err) return func(err);

        let arrayIp = [];
        let arrayNetwork = [];
        document.range_monitored_addresses.forEach((item) => {
            if (~item.indexOf('/')) {
                let [ip, mask] = item.split('/');
                let network = ip + '/' + +mask;
                arrayNetwork.push(network);
            } else {
                arrayIp.push(item);
            }
        });
        arrayIp.sort();
        arrayNetwork.sort();
        let newArray = arrayIp.concat(arrayNetwork);

        document.range_monitored_addresses.toObject();
        document.range_monitored_addresses = newArray;

        func(null, document);
    });
}

//удаление информации
function deleteSource(sourceId, sessionId, func) {
    async.parallel([
        //удаляем источник из таблицы 'sources'
        function(callback) {
            models.modelSource.findOneAndRemove({ 'id': +sourceId }, function(err) {
                if (err) return callback(err);

                if (typeof objGlobals.sources.sourceAvailability[+sourceId] !== 'undefined') {
                    delete objGlobals.sources.sourceAvailability[+sourceId];
                }
                callback(null);
            });
        },
        //удаяляем идентификатор источника из таблици 'session.user.informations'
        function(callback) {
            models.modelSessionUserInformation.update({ session_id: sessionId }, {
                '$pull': { 'user_settings.sourceMainPage': +sourceId }
            }, function(err) {
                if (err) callback(err);
                else callback(null);
            });
        }
    ], function(err) {
        if (err) func(err);
        else func(null, { type: 'success', message: 'источник \'' + sourceId + '\' успешно удален', action: 'reload' });
    });
}