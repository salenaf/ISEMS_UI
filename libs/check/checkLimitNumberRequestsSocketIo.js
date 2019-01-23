/*
 * Проверка на ограничение количества запросов одного типа выполняемых
 * одним пользователем в течении одной минуты
 *
 * Версия 0.1, дата релиза 31.05.2017
 * */

'use strict';

const objGlobals = require('../../configure/globalObject');

module.exports = function(socketIo, typeRequest) {
    //получаем идентификатор пользователя
    let cookie = socketIo.request.headers.cookie.split('; ');
    let sessionId = cookie[0].split('=')[1].split('.')[0].slice(4);

    if (setData()) return true;

    if ((objGlobals.users[sessionId][typeRequest].timeLastQuery < (+new Date) - 60000)) {
        objGlobals.users[sessionId][typeRequest].timeLastQuery = +new Date;
        objGlobals.users[sessionId][typeRequest].countQuery = 1;
        return true;
    }
    if (objGlobals.users[sessionId][typeRequest].countQuery < 15) {
        objGlobals.users[sessionId][typeRequest].countQuery = ++objGlobals.users[sessionId][typeRequest].countQuery;
        return true;
    }

    return false;

    function setData() {
        if (typeof objGlobals.users[sessionId] === 'undefined') {
            objGlobals.users[sessionId] = {};

        }
        if (typeof objGlobals.users[sessionId][typeRequest] === 'undefined') {
            objGlobals.users[sessionId][typeRequest] = {
                'timeLastQuery': +new Date,
                'countQuery': 1
            };
            return true;
        }
        return false;
    }
};