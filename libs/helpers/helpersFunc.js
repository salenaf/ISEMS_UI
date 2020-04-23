"use strict";

const crypto = require("crypto");

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

module.exports.getRandomHex = () => {
    return crypto.randomBytes(20).toString("hex");
};