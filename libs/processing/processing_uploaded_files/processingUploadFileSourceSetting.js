/*
 * Обработка XML файла содержащего информацию о настройках источников
 *
 * Версия 0.1, дата релиза 24.08.2017
 * */

'use strict';

const fs = require('fs');
const path = require('path');
const async = require('async');
const xml2js = require('xml2js');

const models = require('../../../controllers/models');
const objGlobals = require('../../../configure/globalObject');

module.exports = function(fileName, func) {
    new Promise((resolve, reject) => {
        fs.readFile(fileName, 'utf8', (err, file) => {
            if (err) reject(err);
            else resolve(file);
        });
    })
        .then((file) => {
            return new Promise((resolve, reject) => {
                let xmlParser = new xml2js.Parser();
                xmlParser.parseString(file, (err, xmlData) => {
                    if (err) reject(err);
                    else resolve(xmlData);
                });
            });
        })
        .then((xmlData) => {
            if ((typeof xmlData.setup_sources === 'undefined') || (typeof xmlData.setup_sources.source === 'undefined')) {
                throw new Error('malformed xml file');
            }

            let validateArray = checkXmlData(xmlData);

            if (validateArray.length === 0) throw new Error('malformed xml file');

            return validateArray;
        })
        .then((validateArray) => {
            return new Promise((resolve, reject) => {
                var countUpdate = 0,
                    countOverlap = 0;

                async.each(validateArray, (element, callbackEach) => {
                    models.modelSource.collection.insert({
                        'date_register': +element.date_register[0],
                        'date_change': +element.date_change[0],
                        'id': +element.id[0],
                        'short_name': element.short_name[0],
                        'detailed_description': element.detailed_description[0],
                        'ipaddress': element.ipaddress[0],
                        'update_frequency': +element.update_frequency[0],
                        'range_monitored_addresses': element.range_monitored_addresses
                    }, function(err) {
                        if (err) {
                            if (err.code === 11000) {
                                countOverlap++;
                                callbackEach(null);
                            } else {
                                callbackEach(err);
                            }
                        } else {
                            objGlobals.sources.sourceAvailability[+element.id[0]] = {
                                shortName: element.short_name[0],
                                updateFrequency: +element.update_frequency[0],
                                dateLastUpdate: null,
                                statusOld: false,
                                statusNew: false
                            };

                            countUpdate++;
                            callbackEach(null);
                        }
                    });
                }, function(err) {
                    if (err) reject(err);
                    else resolve({
                        'countUpdate': countUpdate,
                        'countOverlap': countOverlap
                    });
                });
            });
        })
        .then((objCount) => {
            fs.unlink(fileName, (err) => {
                if (err) throw err;
                else func(null, objCount);
            });
        })
        .catch((err) => {
            func(err);
        });
};

//валидация данных полученных из xml файла
function checkXmlData(xmlData) {
    let objKeys = {
        'date_register': 'int',
        'date_change': 'int',
        'id': 'int',
        'short_name': 'stringEnInt',
        'detailed_description': 'stringRuEnInt',
        'ipaddress': 'ipaddress',
        'update_frequency': 'int',
        'range_monitored_addresses': 'ipOrNetwork'
    };

    let regexpPattern = {
        int: new RegExp('^[\\d]+$'),
        stringEnInt: new RegExp('^[a-zA-Z0-9_\\-\\s]{3,15}$'),
        stringToken: new RegExp('^[a-zA-Z0-9\\s]+$'),
        stringRuEnInt: new RegExp('^[a-zA-Zа-яА-Яё0-9_\\-\\s\\.,]+$'),
        ipaddress: new RegExp('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$'),
        network: new RegExp('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[/][0-9]{1,2}$')
    };

    function checkFieldMonitoredAddresse(field) {
        if (~field.indexOf('/')) {
            return regexpPattern.network.test(field);
        } else {
            return regexpPattern.ipaddress.test(field);
        }
    }

    let arrayResult = [];
    for (let i = 0; i < xmlData.setup_sources.source.length; i++) {
        let objResult = {};
        for (let key in objKeys) {
            if (typeof xmlData.setup_sources.source[i][key] === 'undefined') continue;

            if (key === 'range_monitored_addresses') {
                if (xmlData.setup_sources.source[i][key][0].indexOf(',')) {
                    let arrayTmp = xmlData.setup_sources.source[i][key][0].split(',');
                    objResult[key] = arrayTmp.filter((item) => {
                        return checkFieldMonitoredAddresse(item);
                    });
                } else {
                    if (checkFieldMonitoredAddresse(xmlData.setup_sources.source[i][key][0])) {
                        objResult[key] = [xmlData.setup_sources.source[i][key][0]];
                    }
                }
            } else {
                if (regexpPattern[objKeys[key]].test(xmlData.setup_sources.source[i][key])) {
                    objResult[key] = xmlData.setup_sources.source[i][key];
                }
            }
        }
        if (Object.keys(objResult).length !== Object.keys(objKeys).length) continue;

        arrayResult.push(objResult);
    }
    return arrayResult;
}