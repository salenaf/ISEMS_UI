/*
* Экспорт файла в формате XML содержащего информацию о настройках источников
*
* Версия 0.1, дата релиза 24.08.2017
* */

'use strict';

const fs = require('fs');
const path = require('path');
const xml2js = require('xml2js');

const models = require('../../../controllers/models');
const writeLogFile = require('../../writeLogFile');
const informationUserGroupPermissions = require('../../informationUserGroupPermissions');

module.exports = function (req, res) {
    new Promise((resolve, reject) => {
        informationUserGroupPermissions(req, function (err, document) {
            if(err) reject(err);

            //проверяем права на доступ к указанной директории
            let readStatus = document.group_settings.management_sources.element_settings.read.status;
            if(readStatus === false) reject(new Error('the user does not have rights to export the file with settings sources'));

            resolve();
        });
    })
        .then(() => {
            return new Promise((resolve, reject) => {
                models.modelSource.find({}, { _id: 0 }, (err, document) => {
                    if(err) return reject(err);

                    let arrayPath = __dirname.split('/');
                    let dirRoot = '';
                    for(let i = 0; i < arrayPath.length - 3; i++){
                        dirRoot += arrayPath[i] + '/';
                    }

                    let file = dirRoot + 'uploads/exportSetupSourcesTmp_' + +new Date() + '.xml';

                    let arrayKeys = [
                        'date_register',
                        'date_change',
                        'id',
                        'short_name',
                        'detailed_description',
                        'ipaddress',
                        'update_frequency',
                        'range_monitored_addresses'
                    ];
                    let newArray = document.map((item) => {
                        let newObj = {};
                        for(let i = 0; i < arrayKeys.length; i++){
                            if(arrayKeys[i] === 'range_monitored_addresses') {
                                newObj[arrayKeys[i]] = item[arrayKeys[i]].join(',');
                            } else {
                                newObj[arrayKeys[i]] = item[arrayKeys[i]];
                            }
                        }
                        return newObj;
                    });

                    let objFinal = { 'setup_sources': { 'source': newArray }};

                    let builder = new xml2js.Builder();
                    try {
                        let xml = builder.buildObject(objFinal);

                        fs.appendFile(file, xml, { 'encoding': 'utf8' }, function(err){
                            if(err) reject(err);
                            else resolve(file);
                        });
                    } catch (err){
                        reject(err)
                    }

                });
            });
        })
        .then((file) => {
            return new Promise((resolve, reject) => {
                fs.access(file, fs.constants.R_OK, function (err) {
                    if(err) reject(err);

                    let fileName = path.basename(file);

                    res.setHeader('Content-disposition', 'attachment; filename=' + fileName);
                    res.setHeader('Content-Type', 'text/xml');

                    let fileStream = fs.createReadStream(file);
                    fileStream.pipe(res);

                    fileStream.on('end', function () {

                        console.log('file name = ' + file);

                        resolve(file);
                    });
                });
            });
        })
        .then((file) => {
            return new Promise((resolve, reject) => {
                fs.unlink(file, function (err) {
                    if(err) reject(err);
                });
            });
        })
        .catch((err) => {
            writeLogFile('error', err.toString());
            res.render('403')
        });
};