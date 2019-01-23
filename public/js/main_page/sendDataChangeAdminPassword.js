/**
 * Модуль отправляющий запрос на изменение стандартного пароля администратора
 * 
 * Версия 0.1, дата релиза 10.01.2018
 */

'use strict';

const md5js = require('md5js');

import checkChangeAdminPassword from './checkChangeAdminPassword';

export default function sendDataChangeAdminPassword() {
    if (!checkChangeAdminPassword()) return;

    let inputPasswordOne = document.getElementById('inputPasswordOne');

    let xhr = new XMLHttpRequest();
    xhr.open('POST', 'change_password', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.send(JSON.stringify({ password: md5js(inputPasswordOne.value).toString() }));

    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            try {
                let resObj = JSON.parse(xhr.responseText);
                common.showNotify(resObj.type, resObj.message);
            } catch (err) {
                common.showNotify('warning', 'некорректный JSON объект');
            }
        }
    };
    $('#modalChangePassAdmin').modal('hide');
}