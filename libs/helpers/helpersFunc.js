"use strict";

const commons = require("./commons");

module.exports.checkUserSettingsManagementUsers = function(userSettings) {
    const checkObj = {
        "user_name": "stringAlphaRu",
        "user_login": "stringAlphaNumEng",
        "work_group": "stringAlphaNumEng",
        "user_password": "stringPasswd",
    };
    let isValide = [];

    if (typeof userSettings === "undefined") {
        return false;
    }

    for (let propName in userSettings) {
        let pattern = commons.getRegularExpression(checkObj[propName]);

        if (pattern.test(userSettings[propName])) {
            isValide.push(true);
        } else {
            isValide.push(false);
        }
    }

    let result = isValide.every(elem => elem === true);

    return result;
};

module.exports.checkInputValidation = (elem) => {
    /*let objSettings = {
        "hostID": new RegExp("^[0-9]{2,}$"),
        "shortNameHost": new RegExp("^[a-zA-Z0-9_№\"\\-\\s]{3,}$"),
        "fullNameHost": new RegExp("^[a-zA-Zа-яА-ЯёЁ0-9_№\"\\-\\s\\.,]{5,}$"),
        "ipaddress": new RegExp("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"),
        "port": new RegExp("^[0-9]{1,5}$"),
        "countProcess": new RegExp("^[0-9]{1}$"),
        "intervalTransmission": new RegExp("^[0-9]{1,}$"),
        "folderStorage": new RegExp("^[\\w\\/_-]{3,}$"),
        "inputDescription": new RegExp("^[\\w\\sа-яА-ЯёЁ().,@№\"!?_-]$"),
        "stringRuNumCharacter": new RegExp("^[а-яА-ЯёЁ0-9\\s.,№-]+$"),
        "stringAlphaRu": new RegExp("^[а-яА-ЯёЁ\\s]{4,}$"),
        "stringAlphaNumEng": new RegExp("^[a-zA-Z0-9_-]{4,}$"),
        "stringPasswd": new RegExp("^[a-zA-Z0-9!@#$%^&*()?]{7,}$"),
    };*/

    /*    let pattern = objSettings[elem.name];

    if(typeof pattern === "undefined"){
        return false;
    }

    if (elem.name === "port") {
        if (!(0 <= elem.value && elem.value < 65536)) return false;
    }
    if (elem.name === "intervalTransmission" && (elem.value < 10)) return false;
    return (!pattern.test(elem.value)) ? false : true;*/
    let pattern = commons.getRegularExpression(elem.name);

    if(typeof pattern === "undefined"){
        return false;
    }

    if (elem.name === "port") {
        if (!(0 <= elem.value && elem.value < 65536)) return false;
    }
    if (elem.name === "intervalTransmission" && (elem.value < 10)) return false;
    return (!pattern.test(elem.value)) ? false : true;
};