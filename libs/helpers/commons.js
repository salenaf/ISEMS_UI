/**
 * Общие вспомогательные функции
 */

"use strict";

module.exports = {
    /**
     * Возвращает регулярное вырожение
     * @param {*} str 
     */
    getRegularExpression(str) {
        let objSettings = {
            "hostID": new RegExp("^[0-9]{2,}$"),
            "shortNameHost": new RegExp("^[a-zA-Z0-9_№\"\\-\\s]{3,}$"),
            "fullNameHost": new RegExp("^[a-zA-Zа-яА-ЯёЁ0-9_№()/\\'\"\\-\\s\\.,]{5,}$"),
            "ipaddress": new RegExp("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"),
            "network": new RegExp("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)/[0-9]{1,2}$"),
            "port": new RegExp("^[0-9]{1,5}$"),
            "countProcess": new RegExp("^[0-9]{1}$"),
            "intervalTransmission": new RegExp("^[0-9]{1,}$"),
            "folderStorage": new RegExp("^[\\w\\/_-]{3,}$"),
            "inputDescription": new RegExp("^[a-zA-Zа-яА-ЯёЁ().,@№\"!?_-\\s]{0,}$"),
            "stringRuNumCharacter": new RegExp("^[а-яА-ЯёЁ0-9\\s.,№-]+$"),
            "stringAlphaRu": new RegExp("^[а-яА-ЯёЁ\\s]{4,}$"),
            "stringAlphaNumEng": new RegExp("^[a-zA-Z0-9_-]{4,}$"),
            "stringPasswd": new RegExp("^[a-zA-Z0-9!@#$%^&*()?]{7,}$"),
            "hexSumMD5": new RegExp("^[a-f0-9]{7,}$"),
        };

        return objSettings[str];
    },
};