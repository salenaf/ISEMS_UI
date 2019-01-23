/**
 * Модуль добавления информации по источнику
 * 
 * Версия 0.1, дата релиза 10.01.2018
 */

'use strict';

import deleteDashboard from './deleteDashboard';

export default function addElementSourceInformation(objectListDashboard, keyId, sourceName) {
    let dashboardSources = document.getElementsByName('dashboardSource');

    if (dashboardSources.length > 0) {
        for (let i = 0; i < dashboardSources.length; i++) {
            if (+dashboardSources[i].dataset.keyId === +keyId) return;
        }
    }
    socket.emit('get source information for dashboard', { sourceId: keyId });

    //создаем новый, пустой дачборд
    createSourceDashboard();

    //выполняем регулярные запросы для получения информации по источнику
    objectListDashboard[keyId] = setInterval((function() {
        socket.emit('get source information for dashboard', { sourceId: keyId });
    }), 60000);

    //формируем новый, пустой дачборд для указанного идентификатора источника
    function createSourceDashboard() {
        let newDashboard = `<div id="source_${keyId}" class="col-sm-12 col-md-12 col-lg-12" name="dashboardSource" data-key-id="${keyId}" style="color: #ccd1d9;">`;
        newDashboard += '<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>';
        newDashboard += `<div name="sourceName" class="text-center" style="color: #888888"><strong>Источник №${keyId} (${sourceName})</strong></div>`;
        newDashboard += '<div name="informationChunkOne" class="col-sm-12 col-md-12 col-lg-12" style="padding-top: 10px;">';
        newDashboard += '<div name="speedValue" class="col-sm-4 col-md-4 col-lg-4"></div><div name="volume" class="col-sm-8 col-md-8 col-lg-8"></div></div>';
        newDashboard += '<div name="speedApplicationProtocols" class="col-sm-12 col-md-12 col-lg-12" style="padding-top: 10px;">';
        newDashboard += '<div class="col-sm-3 col-md-3 col-lg-3">пакеты в секунду (входящие/исходящие)</div>';
        newDashboard += '<div class="col-sm-3 col-md-3 col-lg-3"></div>';
        newDashboard += '<div class="col-sm-3 col-md-3 col-lg-3"></div>';
        newDashboard += '<div class="col-sm-3 col-md-3 col-lg-3"></div></div>';
        newDashboard += '<div name="chart" style="height: 360px; width: 100%; font-size: 11px; margin-top: 60px; padding-bottom: 10px;"></div>';
        //заголовок
        newDashboard += '<div>';
        newDashboard += ' <div class="col-sm-12 col-md-12 col-lg-12 text-center" style="margin-top: 10px; font-size: 10px;">';
        newDashboard += '<div class="col-sm-1 col-md-1 col-lg-1"></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2"><strong>TCP (пакеты / байты)</strong></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2"><strong>UDP (пакеты / байты)</strong></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2"><strong>ICMP (пакеты / байты)</strong></div>';
        newDashboard += '<div class="col-sm-3 col-md-3 col-lg-3"><strong>HTTP (GET / POST / ответы)</strong></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2"><strong>общий объем (пакеты / байты)</strong></div>';
        newDashboard += '</div>';
        //входящие
        newDashboard += '<div name="input" class="col-sm-12 col-md-12 col-lg-12 text-center">';
        newDashboard += '<div class="col-sm-1 col-md-1 col-lg-1 text-left">входящие</div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-3 col-md-3 col-lg-3" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div>';
        newDashboard += '</div>';
        //исходящие
        newDashboard += '<div name="output" class="col-sm-12 col-md-12 col-lg-12 text-center">';
        newDashboard += '<div class="col-sm-1 col-md-1 col-lg-1 text-left">исходящие</div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-3 col-md-3 col-lg-3" style="color: #888888"></div>';
        newDashboard += '<div class="col-sm-2 col-md-2 col-lg-2" style="color: #888888"></div></div>';
        newDashboard += '<div class="col-sm-12 col-md-12 col-lg-12">';
        newDashboard += '<div name="topResolveDm" class="col-sm-2 col-md-2 col-lg-2" style="margin-top: 10px;"></div>';
        newDashboard += '<div class="col-sm-10 col-md-10 col-lg-10">';
        newDashboard += '<div class="text-center" style="font-size: 14px; margin-top: 10px;">Общее количество срабатываний правил СОА (за последний час)</div>';
        newDashboard += '<div name="charAttacks" style="height: 400px; font-size: 11px;"></div>';
        newDashboard += '</div></div></div></div>';

        let divMain = document.createElement('div');
        divMain.setAttribute('style', 'margin-bottom: 5px; height: 1000px; padding-top: 10px; margin-right: 10px; margin-left: 10px; background: white; box-shadow: 1px 1px 1px grey;');
        divMain.innerHTML = newDashboard;

        document.getElementById('listDashboardSource').appendChild(divMain);

        //добавляем обработчик на кнопку 'удалить'
        document.querySelector('#source_' + keyId + ' .close').addEventListener('click', deleteDashboard.bind(null, objectListDashboard));
    }
}