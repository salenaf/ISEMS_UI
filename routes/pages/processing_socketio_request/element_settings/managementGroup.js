/**
 * Модуль обработки событий по управлению группами
 * 
 * Версия 0.1, дата релиза 14.02.2019
 */

'use strict';

module.exports = function() {
    let objData = req.body;
    let processing = {
        'create': createGroup,
        'edit': changeGroup
    };

    if (!(/\b^[a-zA-Z0-9]+$\b/.test(objData.name))) {
        writeLogFile('error', 'incorrect group name');
        return func({ type: 'danger', message: 'некорректное имя группы', action: '' });
    }

    if (objData.actionType === 'delete') {
        return deleteGroup(objData.name, function(err, message) {
            if (err) writeLogFile('error', err.toString());

            func(message);
        });
    }

    checkDataRequest(objData, function(err, objChecked) {
        if (err) {
            writeLogFile('error', err.toString());
            return func({ type: 'danger', message: 'переданы некорректные данные', action: '' });
        }
        if (Object.keys(objChecked).length === 0) {
            writeLogFile('error', err.toString());
            return func({ type: 'danger', message: 'переданы некорректные данные', action: '' });
        } else {
            objChecked.group_name = objData.name;
            objChecked.date_register = +(new Date());

            processing[objData.actionType](objChecked, function(err, message) {
                if (err) writeLogFile('error', err.toString());
                func(message);
            });
        }
    });
};