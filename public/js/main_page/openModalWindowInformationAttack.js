/**
 * Модуль вывода информации по сработавшим сигнатурам
 * 
 * Версия 0.1, дата релиза 10.01.2018
 */

'use strict';

export default function openModalWindowInformationAttack(num, data) {
    let objIpb = {};
    data.value[num].dn.forEach(function(item) {
        if (typeof objIpb[item[0]] === 'undefined') {
            objIpb[item[0]] = { 'id': item[0], 'c': item[1], 'ct': '', 'desc': '' };
        } else {
            objIpb[item[0]].c += item[1];
        }
    });

    let newArray = [];
    let arraySid = [];

    for (let key in objIpb) {
        newArray.push(objIpb[key]);
    }

    newArray.sort(function(a, b) {
        return a.c - b.c;
    });

    newArray.reverse();

    //формируем заголовок
    let dateTmp = data.value[num].d.split('-');
    let stringHeader = 'Подробная информация о событиях информационной безопасности (источник №' + data.sourceId + ') ';
    stringHeader += data.value[num].t + ' ' + dateTmp[2] + '.' + dateTmp[1] + '.' + dateTmp[0];

    let myModalLabel = document.querySelector('#modalInformationAttack #myModalLabel');
    myModalLabel.innerHTML = stringHeader;
    myModalLabel.dataset.sourceId = data.sourceId;

    //формируем поле данных таблицы
    let table = '';
    newArray.forEach(function(item) {
        arraySid.push(item.id);
        table += `<tr data-toggle="tooltip" data-field-sid="${item.id}">`;
        table += `<td class="col-xs-1 text-right">${item.c}</td>`;
        table += `<td class="col-xs-1 text-right">${item.id}</td>`;
        table += '<td class="col-xs-2 text-left"></td>';
        table += '<td class="col-xs-7 text-left"></td></tr>';
    });

    document.querySelector('#modalInformationAttack tbody').innerHTML = table;

    socket.emit('get additional information for sid', { options: { sid: arraySid } });

    $('#modalInformationAttack').modal('show');
}