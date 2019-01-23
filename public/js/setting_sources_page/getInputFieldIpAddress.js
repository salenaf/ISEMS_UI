/**
 * Получение список IP-адресов или сетей
 * 
 * Версия 0.1, дата релиза 30.11.2017
 */

'use strict';

export default function getInputFieldIpAddress() {
    let content = document.querySelectorAll('.tokenfield > .token > span');

    //проверяем валидность контролируемых адресов или подсетей
    let tokensInvalid = document.querySelectorAll('.tokenfield > .invalid');
    if (tokensInvalid.length > 0) return [];

    let result = [];
    for (let i = 0; i < content.length; i++) {
        result.push(content[i].textContent);
    }
    return result;
}