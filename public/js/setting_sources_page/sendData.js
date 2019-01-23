/**
 * Модуль /передачи объекта с данными об источнике на сервер
 * 
 * Версия 0.1, дата релиза 30.11.2017
 */

'use strict';

import editSourceInformation from './editSourceInformation';
import showSourceInformation from './showSourceInformation';

export default function sendData(obj) {
    let xhr = new XMLHttpRequest();
    xhr.open('POST', 'setting_sources', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.send(JSON.stringify(obj));

    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            try {
                let resObj = JSON.parse(xhr.responseText);

                if (typeof resObj.message !== 'undefined') {
                    common.showNotify(resObj.type, resObj.message);
                    if (resObj.action === 'reload') setTimeout(function() {
                        window.location.reload();
                    }, 3000);
                } else {
                    if (resObj.type === 'show') {
                        showSourceInformation(resObj.sourceInformation);
                    } else if (resObj.type === 'edit') {
                        editSourceInformation(resObj.sourceInformation);
                    } else {
                        throw (new Error());
                    }
                }
            } catch (err) {
                common.showNotify('warning', 'некорректный JSON объект');
            }
        }
    };
}