/*
 * Обработка HTTP запросов по работе с пользователями
 *
 * Версия 0.1, дата релиза 06.04.2017
 * */

'use strict';

const models = require('../../../controllers/models');
const hashPassword = require('../../../libs/hashPassword');
const writeLogFile = require('../../../libs/writeLogFile');

module.exports = function(req, res, func) {
    let objData = req.body;

    let processing = {
        'create': createUser,
        'edit': changeUser
    };

    if (!(/\b^[a-zA-Z0-9]+$\b/.test(objData.login))) {
        writeLogFile('error', 'incorrect login name');
        return func({ type: 'danger', message: 'некорректное имя пользователя', action: '' });
    }

    if (objData.actionType === 'delete') {
        return deleteUser(objData.login, function(err, message) {
            if (err) writeLogFile('error', err.toString());
            func(message);
        });
    }

    let loginIsTrue = /\b^[a-zA-Z0-9]{4,}$\b/.test(objData.login);
    let groupIsTrue = /\b^[a-zA-Z0-9]{4,}$\b/.test(objData.group);
    let userNameIsTrue = /^[а-яё\s]+$/i.test(objData.userName);

    if (loginIsTrue && groupIsTrue && userNameIsTrue) {
        let passwordHash = hashPassword.getHashPassword(objData.password, 'waterfall-ui');
        processing[objData.actionType](objData, passwordHash, function(err, message) {
            if (err) writeLogFile('error', err.toString());
            func(message);
        });
    }
};

//создание нового пользователя
function createUser(obj, passwordHash, func) {
    models.modelUser.findOne({ login: obj.login }, { login: 1, _id: 0 }, function(err, login) {
        if (err) return func(err);

        if (login !== null) return func(null, { type: 'warning', message: 'пользователь с таким именем уже существует', action: '' });

        models.modelUser.collection.insert({
            'date_register': +(new Date()),
            'date_change': +(new Date()),
            'login': obj.login,
            'group': obj.group,
            'user_name': obj.userName,
            'password': passwordHash,
            'settings': { 'sourceMainPage': [] }
        }, function(err) {
            if (err) func(err);
            else func(null, { type: 'success', message: 'пользователь успешно добавлен', action: 'reload' });
        });
    });
}

//изменение информации о пользователе
function changeUser(obj, passwordHash, func) {
    models.modelUser.findOneAndUpdate({ login: obj.login }, {
        'date_change': +(new Date()),
        'group': obj.group,
        'user_name': obj.userName,
        'password': passwordHash
    }, function(err) {
        if (err) func(err);
        else func(null, { type: 'success', message: 'информация о пользователе изменена', action: 'reload' });
    });
}

//удаление пользователя
function deleteUser(login, func) {
    models.modelUser.findOneAndRemove({ login: login }, function(err) {
        if (err) return func(err);

        func(null, { type: 'success', message: 'пользователь успешно удален', action: 'reload' });
    });
}