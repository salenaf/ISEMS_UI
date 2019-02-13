/*
 * Информация о правах группы к которой относится пользователь
 *
 * Версия 0.11, дата релиза 13.02.2019
 * */

'use strict';

const models = require('../controllers/models');
const mongodbQueryProcessor = require('../middleware/mongodbQueryProcessor');

module.exports = function(req, cb) {
    mongodbQueryProcessor.querySelect(models.modelSessionUserInformation, {
        query: { session_id: req.sessionID }
    }, (err, result) => {
        if (err) cb(err);
        else cb(null, result)
    })

    /*models.modelSessionUserInformation.findOne({ session_id: req.sessionID }, (err, groupData) => {
        if(err) return func(new Error('the group model is not defined'));

        cb(null, groupData);
    });*/
};