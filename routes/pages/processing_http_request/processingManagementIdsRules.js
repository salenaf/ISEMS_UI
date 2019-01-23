/*
 * Обработка HTTP запросов по работе с правилами СОА
 *
 * Версия 0.1, дата релиза 26.07.2017
 * */

'use strict';

const async = require('async');
const validate = require('validate.js');

const models = require('../../../controllers/models');
const writeLogFile = require('../../../libs/writeLogFile');
const usersSessionInformation = require('../../../libs/mongodb_requests/usersSessionInformation');

module.exports = function (req, res, func) {
    let objData = req.body;
    let processing = {
        'create': createGroup,
        'edit': changeGroup
    };

    func();
};

//валидация входных параметров и подготовка финального объекта
function checkDataRequest (objData, func) {
    let patternSettingObj = {
        menu_items: 'пункты меню',
        management_groups : 'группы',
        management_sources : 'источники',
        management_users : 'пользователи'
    };
    let patternTypeActionObj = {
        create : "создание",
        read : "просмотр",
        edit : "редактирование",
        delete : "удаление"
    };
    let patternMenuObj = {
        setting_groups : "группы пользователей",
        setting_users : "пользователи",
        setting_sources : "источники"
    };

    let finalObj = {};
    try {
        for(let patternNameSetting in patternSettingObj){
            finalObj[patternNameSetting] = {};
            finalObj[patternNameSetting].name = patternSettingObj[patternNameSetting];
            finalObj[patternNameSetting].element_settings = {};
            if(patternNameSetting === 'menu_items'){
                for(let patternNameMenu in patternMenuObj){
                    finalObj[patternNameSetting].element_settings[patternNameMenu] = {};
                    finalObj[patternNameSetting].element_settings[patternNameMenu].description = patternMenuObj[patternNameMenu];

                    let status = objData[patternNameSetting][patternNameMenu];
                    if(validate.isBoolean(status)){
                        finalObj[patternNameSetting].element_settings[patternNameMenu].status = objData[patternNameSetting][patternNameMenu];
                    }
                }
            } else {
                for(let patternNameTypeAction in patternTypeActionObj){
                    finalObj[patternNameSetting].element_settings[patternNameTypeAction] = {};
                    finalObj[patternNameSetting].element_settings[patternNameTypeAction].description = patternTypeActionObj[patternNameTypeAction];

                    let status = objData[patternNameSetting][patternNameTypeAction];
                    if(validate.isBoolean(status)){
                        finalObj[patternNameSetting].element_settings[patternNameTypeAction].status = objData[patternNameSetting][patternNameTypeAction];
                    }
                }
            }
        }
    } catch (err){
        return func(err);
    }
    func(null, finalObj);
}


//создание группы
function createRulesIds (func) {

}

//удаление правил (всех или по одному)
function deleteRulesIds (func) {

}