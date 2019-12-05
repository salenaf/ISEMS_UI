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