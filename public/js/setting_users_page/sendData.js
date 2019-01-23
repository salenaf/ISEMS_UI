/**
 * Модуль отправки данных методом httpxmlrequest 
 * 
 * Версия 0.1, дата релиза 29.11.2017
 */

'use strict';

export default function sendData(obj) {
    let xhr = new XMLHttpRequest();
    xhr.open('POST', 'setting_users', true);
    xhr.setRequestHeader('Content-Type', 'application/json');

    xhr.send(JSON.stringify(obj));

    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.status === 200) {
            try {
                let resObj = JSON.parse(xhr.responseText);

                common.showNotify(resObj.type, resObj.message);
                if (resObj.action === 'reload') setTimeout(function() {
                    window.location.reload();
                }, 3000);
            } catch (err) {
                common.showNotify('warning', 'некорректный JSON объект');
            }
        }
    };
}