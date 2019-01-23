/**
 * Модуль проверки изменений выполненных в поле ввода
 * 
 * Версия 0.1, дата релиза 30.11.2017
 */

'use strict';

export default function checkChangeInputIpAddress() {
    let divParentNode = document.getElementById('networkSegmentRange');
    let tokenInvalid = divParentNode.parentNode.getElementsByClassName('invalid');
    let token = divParentNode.parentNode.getElementsByClassName('token');

    if (token.length === 0) {
        divParentNode.parentNode.parentNode.classList.remove('has-error');
        divParentNode.parentNode.parentNode.classList.remove('has-success');
    }

    if ((tokenInvalid.length === 0) && (token.length > 0)) {
        divParentNode.parentNode.parentNode.classList.remove('has-error');
        divParentNode.parentNode.parentNode.classList.add('has-success');
    }
}