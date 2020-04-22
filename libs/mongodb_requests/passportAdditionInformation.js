"use strict";

const models = require("../../controllers/models");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");

/**
 * добавление документа в passport_addition_information
 * 
 * @param{*} - userName
 * @param{*} - passportTD
 * @param{*} - isDefaultPassword
 * @param{*} - callback
 */
module.exports.create = (userName, passportID, isDefaultPassword, callback) => {
//записываем информацию о пользователе по его passport ID 
    new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelAdditionalPassportInformation, {
            query: { passport_id: passportID },
        }, (err, result) => {
            if(err) reject(err);
            if(result !== null){
                return callback(null, {
                    id: passportID,
                    username: userName
                });
            }

            resolve();
        });
    }).then(() => {
        return new Promise((resolve, reject) => {
            mongodbQueryProcessor.queryCreate(models.modelAdditionalPassportInformation, {
                document: {
                    passport_id: passportID,
                    login: userName,
                    is_admin_password_default: isDefaultPassword
                }
            }, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    }).then(() => {
        callback(null, {
            id: passportID,
            username: userName
        });
    }).catch((err) => {
        callback(err);
    });
};

/**
 * удаление документа из passport_addition_information
 * 
 * @param{*} - passportTD
 * @param{*} - callback
 */
module.exports.delete = (passportID, callback) => {
    new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(models.modelSessionUserInformation,{
            isMany: true,
            query: { passport_id: passportID },
        }, (err, result) => {
            if(err) reject(err);
            else resolve(result);
        });
    }).then((listsessionUserInfo) => {
        if(listsessionUserInfo.length > 0){
            return callback(null);
        }

        mongodbQueryProcessor.queryDelete(
            models.modelAdditionalPassportInformation,
            { query: { passport_id: passportID } },
            (err) => {
                if(err) callback(err);
                else callback(null); 
            }
        );
    }).catch((err) => {
        callback(err);
    });
};