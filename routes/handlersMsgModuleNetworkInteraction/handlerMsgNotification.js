"use strict";

/**
 * Обработчик информационных сообщений приходящих от модуля ISEMS-NIH
 * 
 * @param {*} notification - сообщение от модуля ISEMS-NIH в формате JSON
 */
module.exports = (notification) => {
    new Promise((resolve, reject) => {
        require("../../middleware/mongodbQueryProcessor").queryInsertMany(require("../../controllers/models").modelNotificationLogISEMSNIH, {
            id: notification.taskID,
            date_register: +(new Date),
            type: notification.options.n.t,
            source_id: notification.options.n.s,
            message: notification.options.n.d,
        }, (err) => {
            if(err) reject(err);
            else resolve();
        });
    //    require("../../middleware/mongodbQueryProcessor").querySelect(require("../../controllers/models").modelSourcesParameter, {
    }).catch((err) => {
        require("../../libs/writeLogFile")("error", `${err.toString()} (func 'handlerMsgNotificationModuleISEMS-NIH')`);
    });
};