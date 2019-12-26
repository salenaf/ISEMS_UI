/**
 * Модуль обработчик дейсвий над группами пользователей
 * 
 * Версия 1.1, дата релиза 25.12.2019
 */

"use strict";

const debug = require("debug")("handlerActionsGroups");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const createUniqID = require("../../libs/helpers/createUniqID");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
//const managemetGroups = require("./pages/processing_socketio_request/element_settings/managementGroup");

module.exports.addHandlers = function(socketIo) {
    const handlers = {
        "add new group": addGroup,
        "update group": updateGroup,
        "delete group": deleteGroup,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function addGroup(socketIo, data) {
    debug("ADDITION NEW GROUP");
    debug(data);

    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then(authData => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("group management", "Пользователь не авторизован.");
            }

            debug("авторизован ли пользователь, YES");

            //может ли пользователь создавать новоую группу пользователей
            if (!authData.document.groupSettings.management_groups.element_settings.create.status) {
                throw new MyError("group management", "Невозможно добавить новоую группу пользователей. Недостаточно прав на выполнение данного действия.");
            }

            debug("может ли пользователь создавать новоую группу пользователей, YES");

            const errMsg = "Невозможно добавить новоую группу пользователей. Один или более заданных параметров некорректен.";

            if (typeof data.arguments === "undefined") {

                debug(`ERROR 1: '${errMsg}'`);

                throw new MyError("group management", errMsg);
            }

            if (typeof data.arguments.groupName === "undefined") {

                debug(`ERROR 2: '${errMsg}'`);

                throw new MyError("group management", errMsg);
            }

            let groupName = data.arguments.groupName;

            if (!(/\b^[a-zA-Z0-9]+$\b/.test(groupName))) {

                debug("ERROR 3: 'Невозможно добавить новоую группу пользователей. Задано неверное имя группы.'");

                throw new MyError("group management", "Невозможно добавить новоую группу пользователей. Задано неверное имя группы.");
            }

        }).then(() => {

            debug("формируем шаблон будущей группы");

            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelGroup, {
                    query: { group_name: "administrator" },
                    select: { _id: 0, __v: 0, date_register: 0, group_name: 0 }
                }, (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
        }).then(results => {

            debug("шаблон будущей группы...");
            //debug(results);
            debug("формируем новый объект группы");

            let changeStatus = (groupName, objData) => {
                let { id, state, listElements, count } = objData;
                if (count > 10) return;

                if ( /*(typeof listElements.id !== "undefined") &&*/ (typeof listElements.status === "undefined")) {
                    listElements.id = createUniqID.getMD5(groupName + listElements.id);
                }

                for (let item in listElements) {
                    if (typeof listElements[item] !== "object") continue;
                    //                    if (typeof listElements[item].id === "undefined") continue;

                    let actualID = listElements[item].id;
                    if (actualID !== id) {
                        changeStatus(data.arguments.groupName, {
                            id: id,
                            state: state,
                            listElements: listElements[item],
                            count: ++count
                        });

                        continue;
                    }

                    listElements[item].status = state;
                    listElements[item].id = createUniqID.getMD5(groupName + actualID);
                }
            };

            let listElements = results.toObject();
            for (let hex in data.arguments.listPossibleActions) {
                for (let key in listElements) {
                    if (key === "id") continue;

                    changeStatus(data.arguments.groupName, {
                        id: hex,
                        state: data.arguments.listPossibleActions[hex],
                        listElements: listElements[key],
                        count: 0
                    });
                }
            }

            listElements = Object.assign(listElements, {
                group_name: data.arguments.groupName,
                date_register: +(new Date())
            });

            return listElements;
        }).then(newGroup => {

            debug("записываем новый объект группы в БД");

            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryCreate(models.modelGroup, { document: newGroup }, err => {
                    if (err) reject(err);
                    else resolve(newGroup);
                });
            });
        }).then(newGroup => {
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Новая группа пользователей успешно добавлена."
            });

            let groupName = newGroup.group_name;
            let sendNewGroup = {
                "date_register": newGroup.date_register,
                "group_name": groupName,
            };

            delete newGroup["id"];
            delete newGroup["group_name"];
            delete newGroup["date_register"];

            sendNewGroup[groupName] = newGroup;

            debug(sendNewGroup);
            debug("_______________________");

            socketIo.emit("add new group", JSON.stringify(sendNewGroup));
        }).catch(err => {
            if (err.name === "group management") {
                return showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            }

            showNotify({
                socketIo: socketIo,
                type: "danger",
                message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
            });

            writeLogFile("error", err.toString());
        });
}

function updateGroup(socketIo, data) {

}

function deleteGroup(socketIo, data) {

}