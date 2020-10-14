/*
 * Поиск подробной, дополнительной информации по идентификатору сигнатуры
 *
 * Версия 0.1, 18.08.2017
 * */

'use strict';

const models = require('../../../controllers/models/index');

module.exports = function(data, func) {
    let arraySearchSid = (Array.isArray(data.options.sid)) ? data.options.sid : checkSid(data.options.sid);

    if (arraySearchSid.length === 0) return func(new Error('taken incorrect data, incorrect sid'));

    models.modelRulesIDS.find({ sid: { '$in': arraySearchSid } }, { _id: 0, sid: 1, classType: 1, msg: 1, body: 1 }, (err, document) => {
        if (err) func(err);
        else func(null, document);
    });
};

//проверка идентификаторов решающих правил СОА
function checkSid(stringSid) {
    if (!~stringSid.indexOf(',')) return (/^\d+$/.test(stringSid)) ? [stringSid] : [];

    let arrayTmp = stringSid.split(',');
    return arrayTmp.filter((sid) => {
        return (/^\d+$/.test(sid));
    });
}