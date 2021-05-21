"use strict";

const crypto = require("crypto");

const commons = require("./commons");
const globalObject = require("../../configure/globalObject");

module.exports.checkUserSettingsManagementUsers = function (userSettings) {
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

    if (typeof pattern === "undefined") {
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

module.exports.getCountConnectionSources = (go) => {
    let obj = {
        numConnect: 0,
        numDisconnect: 0,
        numProcessDownload: 0,
        numProcessFiltration: 0,
        numTasksNotDownloadFiles: 0,
    };
    let sources = go.getData("sources");
    for (let source in sources) {
        if (sources[source].connectStatus) {
            obj.numConnect++;
        } else {
            obj.numDisconnect++;
        }
    }

    return obj;
};

module.exports.modifyListFoundTasks = (oldList) => {
    let tmpSource = {
        sid: 0,
        name: "",
    };

    return oldList.map((item) => {
        if (tmpSource.sid === item.sid) {
            item.sn = tmpSource.name;

            return item;
        }

        if (!globalObject.hasData("sources", item.sid)) {
            item.sn = "нет данных";
        } else {
            let sourceInfo = globalObject.getData("sources", item.sid);
            tmpSource = {
                sid: item.sid,
                name: sourceInfo.shortName,
            };

            item.sn = sourceInfo.shortName;
        }

        return item;
    });
};

module.exports.sendMessageByUserSocketIo = (userSocketId, e, msg) => {
    let socketIo = globalObject.getData("descriptionSocketIo", "userConnections", userSocketId);
    if (socketIo !== null) {
        socketIo.emit(e, msg);

        return true;
    }

    return false;
};

//Широковещательное сообщение по socket.io
module.exports.sendBroadcastSocketIo = (e, msg) => {
    let socketIo = globalObject.getData("descriptionSocketIo", "majorConnect");

    if (socketIo !== null) {
        socketIo.emit(e, msg);
    }
};