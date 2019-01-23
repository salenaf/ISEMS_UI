/**
 * Модуль удаления дачборда
 * 
 * Версия 0.1, дата релиза 10.01.2018
 */

'use strict';

export default function deleteDashboard(objectListDashboard, event) {
    let mainParent = event.target.parentElement.parentElement.parentElement;
    let keyId = event.target.parentElement.dataset.keyId;

    mainParent.removeChild(event.target.parentElement.parentElement);

    socket.emit('delete source id dashboard', { sourceId: keyId });

    clearInterval(objectListDashboard[keyId]);
    delete objectListDashboard[keyId];
}