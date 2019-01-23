/*
* Обработка HTTP запросов по работе с группами пользователей
*
* Версия 0.1, дата релиза 06.04.2017
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

    if(!(/\b^[a-zA-Z0-9]+$\b/.test(objData.name))){
        writeLogFile('error', 'incorrect group name');
        return func({ type: 'danger', message: 'некорректное имя группы', action: '' });
    }

    if(objData.actionType === 'delete'){
        return deleteGroup(objData.name, function (err, message) {
            if(err) writeLogFile('error', err.toString());

            func(message);
        });
    }

    checkDataRequest(objData, function(err, objChecked) {
        if(err){
            writeLogFile('error', err.toString());
            return func({ type: 'danger', message: 'переданы некорректные данные', action: '' });
        }
        if(Object.keys(objChecked).length === 0){
            writeLogFile('error', err.toString());
            return func({ type: 'danger', message: 'переданы некорректные данные', action: '' });
        } else {
            objChecked.group_name = objData.name;
            objChecked.date_register = +(new Date());

            processing[objData.actionType](objChecked, function (err, message) {
                if(err) writeLogFile('error', err.toString());
                func(message);
            });
        }
    });
};

//валидация входных параметров и подготовка финального объекта
function checkDataRequest (objData, func) {
    let patternSettingObj = {
        menu_items: 'пункты меню',
        management_groups : 'группы',
        management_sources : 'источники',
        management_users : 'пользователи',
        management_ids_rules: 'правила СОА',
        management_search_rules: 'правила поиска',
        management_geoip: 'GeoIP',
        management_reputational_lists: 'репутационные списки',
        management_events: 'события'
    };
    let patternMenuObj = {
        setting_groups: 'группы пользователей',
        setting_users: 'пользователи',
        setting_sources: 'источники',
        setting_ids_rules: 'правила СОА',
        setting_search_rules: 'правила поиска',
        setting_geoip: 'GeoIP',
        setting_reputational_lists: 'репутационные списки'
    };

    let finalObj = {};
    try {
        for(let patternNameSetting in patternSettingObj){
            finalObj[patternNameSetting] = {};
            finalObj[patternNameSetting].name = patternSettingObj[patternNameSetting];
            finalObj[patternNameSetting].element_settings = {};
            if(patternNameSetting === 'menu_items') {
                for (let patternNameMenu in patternMenuObj) {
                    finalObj[patternNameSetting].element_settings[patternNameMenu] = {};
                    finalObj[patternNameSetting].element_settings[patternNameMenu].description = patternMenuObj[patternNameMenu];

                    let status = objData[patternNameSetting][patternNameMenu];
                    if (validate.isBoolean(status)) {
                        finalObj[patternNameSetting].element_settings[patternNameMenu].status = objData[patternNameSetting][patternNameMenu];
                    }
                }
            } else {
                let patternTypeActionObj = {
                    create : "создание",
                    read : "просмотр",
                    edit : "редактирование",
                    delete : "удаление"
                };

                if(patternNameSetting === 'management_ids_rules' || patternNameSetting === 'management_geoip'){
                    delete patternTypeActionObj.edit;
                }
                if(patternNameSetting === 'management_events'){
                    delete patternTypeActionObj.create;
                    delete patternTypeActionObj.edit;
                }

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
function createGroup (obj, func) {
    models.modelGroup.find({ group_name: obj.group_name }, function (err, result) {
        if(err) return func(err);

        if(result.length !== 0) return func(null, { type: 'warning', message: 'группа с таким названием уже существует', action: '' });

        models.modelGroup.collection.insert(obj, function (err) {
            if(err) func(err);
            else func(null, { type: 'success', message: 'группа успешно добавлена', action: 'reload' });
        });
    });
}

//изменение информации о группе
function changeGroup (obj, func) {
    let name = obj.group_name;
    delete obj.group_name;
    delete obj.date_register;

    async.parallel([
        //изменяем параметры в db.groups
        function (callback) {
            models.modelGroup.findOneAndUpdate({ group_name: name }, obj, function (err) {
                if(err) callback(err);
                else callback(null);
            });
        },
        //изменяем параметры в db.session.user.information
        function (callback) {
            usersSessionInformation.changeGroupSettings(name, obj, function (err) {
                if(err) callback(err);
                else callback(null);
            });
        }
    ], function(err) {
        if(err) func(err);
        else func(null, { type: 'success', message: 'информация о группе изменена успешно', action: '' });
    });
}

//удаление группы
function deleteGroup (groupName, func) {
    //проверяем принадлежность пользователей к удаляемой группе
    models.modelUser.find({ group: groupName }, { _id: 1 }, function (err, document) {
        if(err) return func(err);

        if(Object.keys(document).length !== 0) return func(null, { type: 'warning', message: 'невозможно удалить группу \'' + groupName +  '\', так как существуют пользователи принадлежащие к данной группе', action: '' });

        models.modelGroup.findOneAndRemove({ group_name: groupName }, function (err) {
            if(err) return func(err);

            func(null, { type: 'success', message: 'группа успешно удалена', action: 'reload' });
        });
    });
}
