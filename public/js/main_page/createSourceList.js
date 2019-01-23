/**
 * Модуль построения нового списка источников
 * 
 * Версия 0.1, дата релиза 10.01.2018
 */

'use strict';

let createSourceList = {
    sourceList: function(obj) {
        let newElement = '';
        for (let key in obj) {
            let status = (obj[key].statusConnection) ? 'my_circle_green' : 'my_circle_red';

            newElement += '<li style="padding-bottom: 3px;">';
            newElement += `<canvas class="${status}"></canvas>&nbsp;&nbsp;<a href="#">${key}&nbsp;${obj[key].shortName}</a></li>`;
        }

        var elemListSource = document.getElementById('sourcesList');
        elemListSource.innerHTML = newElement;
    },
    settingSourceList: function(obj) {
        let newElement = '<i class="btn dropdown-toggle glyphicon glyphicon-cog" data-toggle="dropdown"></i>';
        newElement += '<ul class="dropdown-menu pull-right">';
        for (let key in obj) {
            newElement += `<li style="padding-bottom: 3px;"><a href="#" data-key-id="<%= key %>">${key}&nbsp;${obj[key].shortName}</a></li>`;
        }
        newElement += '</ul>';

        let elemListSource = document.getElementById('listSettingSources');
        elemListSource.innerHTML = newElement;
    }
};

export default createSourceList;