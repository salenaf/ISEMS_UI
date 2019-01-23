/**
 * Модуль проверки вводимых данных
 * 
 * Версия 0.1, дата релиза 30.11.2017
 */

'use strict';

export default function checkInputValidation(elem) {
    let objSettings = {
        'hostId': new RegExp('^[0-9]{1,7}$'),
        'shortNameHost': new RegExp('^[a-zA-Z0-9_\\-\\s]{3,15}$'),
        'fullNameHost': new RegExp('^[a-zA-Zа-яА-Яё0-9_\\-\\s\\.,]{5,}$'),
        'ipaddress': new RegExp('^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$'),
        'intervalReceiving': new RegExp('^[0-9]{1,3}$')
    };
    let pattern = objSettings[elem.name];

    if (elem.name === 'port') {
        if (!(0 <= elem.value && elem.value < 65536)) return false;
    }
    if (elem.name === 'intervalTransmission' && (elem.value < 10)) return false;

    return (!pattern.test(elem.value)) ? false : true;
}