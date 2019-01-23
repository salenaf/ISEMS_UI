/**
 * Модуль формирующий модальное окно с информацией об источнике
 * 
 * Версия 0.1, дата релиза 30.11.2017
 */

'use strict';

import { IPv4_Address } from '../common_helpers/networkCalc';

export default function showSourceInformation(object) {
    function intConvert(nLoad) {
        let newString = nLoad.toString();
        let interimArray = [];
        let countCycles = Math.ceil((newString.length / 3));
        let num = 0;

        for (let i = 1; i <= countCycles; i++) {
            interimArray.push(newString.charAt(newString.length - 3 - num) + newString.charAt(newString.length - 2 - num) + newString.charAt(newString.length - 1 - num));
            num += 3;
        }

        interimArray.reverse();
        return interimArray.join(' ');
    }

    //формируем заголовок
    document.querySelector('#modalShowRemoteHosts .modal-header > .modal-title').innerHTML = 'Источник №' + object.id + ' (' + object.short_name + ')';
    let objSettings = {
        'id': ['Цифровой идентификатор источника:', false],
        'short_name': ['Краткое название источника:', false],
        'date_register': ['Дата добавления:', true],
        'date_change': ['Дата изменения:', true],
        'detailed_description': ['Полное описание источника:', false],
        'update_frequency': ['Интервал приема информации в секундах:', false],
        'ipaddress': ['IP-адрес источника:', false]
    };
    let x = (new Date()).getTimezoneOffset() * 60000;

    let container = document.createElement('div');
    container.classList.add('container-fluid');

    let divRow = document.createElement('div');
    divRow.classList.add('row');

    let divCol = document.createElement('div');
    divCol.classList.add('col-sm-6', 'col-md-6', 'col-lg-6');
    divCol.setAttribute('style', 'margin-top: 5px;');

    let divClearfix = document.createElement('div');
    divClearfix.classList.add('clearfix');

    for (let key in objSettings) {
        let newDivClearfix = divClearfix.cloneNode(false);
        let divName = divCol.cloneNode(false);
        divName.classList.add('text-right', 'strong');
        divName.innerHTML = `<strong>${objSettings[key][0]}</strong>`;
        divRow.appendChild(divName);

        let divValue = divCol.cloneNode(false);
        divValue.classList.add('text-left');
        let value = object[key];
        if (objSettings[key][1] === true) {
            value = (+object[key] === 0) ? 'дата не определена' : (new Date((+object[key]) - x)).toISOString().slice(0, -1).replace(/T/, ' ').replace(/\..+/, '');
        }
        divValue.appendChild(document.createTextNode(value));
        divRow.appendChild(divValue);

        divRow.appendChild(newDivClearfix);
    }
    container.appendChild(divRow);

    let divRangeMonitoredAddress = document.createElement('div');
    divRangeMonitoredAddress.classList.add('col-sm-12', 'col-md-12', 'col-lg-12');
    divRangeMonitoredAddress.setAttribute('style', 'margin-top: 5px;');

    let divHead = divRangeMonitoredAddress.cloneNode(false);
    divHead.classList.add('text-center');
    divHead.innerHTML = '<strong>IP-адреса или подсети контролируемого сегмента:</strong>';
    divRangeMonitoredAddress.appendChild(divHead);

    let divList = divRangeMonitoredAddress.cloneNode(false);
    divList.classList.add('text-center');
    let listIpNetwork = '';

    object.range_monitored_addresses.forEach((item) => {
        let string = '';
        if (~item.indexOf('/')) {
            let arrIpMask = item.split('/');

            let ipv4Address = new IPv4_Address(arrIpMask[0], arrIpMask[1]);
            let countIpAddress = (parseFloat(ipv4Address.netbcastInteger) - parseFloat(ipv4Address.netaddressInteger) + 1);
            string = ipv4Address.netaddressDotQuad + ' - ' + ipv4Address.netbcastDotQuad + ' (' + arrIpMask[1] + '),';
            string += ' всего адресов: ' + intConvert(countIpAddress);
        } else {
            string = item + ' (32), всего адресов: 1';
        }
        listIpNetwork += `<div>${string}</div>`;
    });
    divList.innerHTML = listIpNetwork;
    divRangeMonitoredAddress.appendChild(divList);
    container.appendChild(divRangeMonitoredAddress);

    let divElementBody = document.querySelector('#modalShowRemoteHosts .modal-body');
    divElementBody.innerHTML = '';
    divElementBody.appendChild(container);

    $('#modalShowRemoteHosts').modal('show');
}