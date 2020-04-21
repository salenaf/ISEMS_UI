"use strict";

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const showNotify = require("../../libs/showNotify");
const createUniqID = require("../../libs/helpers/createUniqID");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");

/**
 * Модуль для управления группами пользователей
 * 
 * @param {*} socketIo - object
 */
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
    const errMsg = "Невозможно добавить новую группу пользователей. Получены некорректные данные.";
    if(typeof data.arguments === "undefined"){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: errMsg,
        });

        writeLogFile("error", errMsg);

        return;
    }

    if((typeof data.arguments.groupName === "undefined") || (typeof data.arguments.listPossibleActions === "undefined")){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: errMsg,
        });

        writeLogFile("error", errMsg);

        return;
    }

    let groupName = data.arguments.groupName;
    let listPossibleActions = data.arguments.listPossibleActions;

    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("group management", "Пользователь не авторизован.");
            }

            //может ли пользователь создавать новоую группу пользователей
            if (!authData.document.groupSettings.management_groups.element_settings.create.status) {
                throw new MyError("group management", "Невозможно добавить новую группу пользователей. Недостаточно прав на выполнение данного действия.");
            }

            if (!(/\b^[a-zA-Z0-9_-]+$\b/.test(groupName))) {
                throw new MyError("group management", "Невозможно добавить новую группу пользователей. Задано неверное имя группы.");
            }

        }).then(() => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelGroup, {
                    query: { group_name: groupName },
                    select: { _id: 0, __v: 0, date_register: 0, group_name: 0 }
                }, (err, results) => {
                    if (err) reject(err);
                    if(!results){
                        resolve();
                    }

                    reject(new MyError("group management", "Невозможно добавить новую группу пользователей. Группа с таким именем уже существует."));
                });
            });
        }).then(() => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelGroup, {
                    query: { group_name: "administrator" },
                    select: { _id: 0, __v: 0, date_register: 0, group_name: 0 }
                }, (err, results) => {
                    if (err) reject(err);
                    else resolve(results);
                });
            });
        }).then((results) => {
            let changeStatus = (groupName, objData) => {
                let { id, state, listElements, count } = objData;
                if (count > 10) return;

                if (typeof listElements.status === "undefined") {
                    listElements.id = createUniqID.getMD5(groupName + listElements.id);
                }

                for (let item in listElements) {
                    if (typeof listElements[item] !== "object") continue;

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
            for (let hex in listPossibleActions) {
                for (let key in listElements) {
                    if (key === "id") continue;

                    changeStatus(data.arguments.groupName, {
                        id: hex,
                        state: listPossibleActions[hex],
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
        }).then((newGroup) => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryCreate(models.modelGroup, { document: newGroup }, err => {
                    if (err) reject(err);
                    else resolve(newGroup);
                });
            });
        }).then((newGroup) => {
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

            delete newGroup.id;
            delete newGroup.group_name;
            delete newGroup.date_register;

            sendNewGroup[groupName] = newGroup;

            socketIo.emit("add new group", JSON.stringify(sendNewGroup));
        }).catch((err) => {
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
    const errMsg = "Невозможно изменить информацию о группе. Получены некорректные данные.";
    if(typeof data.arguments === "undefined"){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: errMsg,
        });

        writeLogFile("error", errMsg);

        return;
    }

    if((typeof data.arguments.groupName === "undefined") || (typeof data.arguments.listPossibleActions === "undefined")){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: errMsg,
        });

        writeLogFile("error", errMsg);

        return;
    }

    let groupName = data.arguments.groupName;
    let listPossibleActions = data.arguments.listPossibleActions;

    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("group management danger", "Пользователь не авторизован.");
            }

            //может ли пользователь редактировать информацию о группе пользователей
            if (!authData.document.groupSettings.management_groups.element_settings.edit.status) {
                throw new MyError("group management danger", "Невозможно изменить информацию о группе. Недостаточно прав на выполнение данного действия.");
            }

            if (!(/\b^[a-zA-Z0-9_-]+$\b/.test(groupName))) {
                throw new MyError("group management danger", "Невозможно изменить информацию о группе. Задано неверное имя группы.");
            }

        }).then(() => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelGroup, {
                    query: { group_name: groupName }
                }, (err, results) => {
                    if (err) reject(err);
                    if(!results){
                        reject(new MyError("group management danger", "Невозможно изменить информацию о группе. Группы с таким именем не существует."));
                    }

                    resolve(results);
                });
            });
        }).then((groupInfo) => {
            let testCountElemStatus = function(obj){
                let result = {
                    countIsTrue: 0,
                    countIsFalse: 0,             
                };

                let rangeElem = (list) => {
                    for(let item in list){
                        if(typeof list[item] !== "object") continue;
            
                        if(typeof list[item].status !== "undefined"){
                            if(list[item].status) result.countIsTrue++;
                            else result.countIsFalse++;
                        } else {
                            rangeElem(list[item]);
                        }
                    }
                };

                rangeElem(obj);

                return result;
            };

            const changeStatus = (objData) => {
                let { id, state, listElements, count } = objData;
                if (count > 10) return;

                for (let item in listElements) {
                    if (typeof listElements[item] !== "object") continue;

                    let actualID = listElements[item].id;
                    if (actualID !== id) {
                        changeStatus({
                            id: id,
                            state: state,
                            listElements: listElements[item],
                            count: ++count
                        });

                        continue;
                    }

                    if(listElements[item].id === id){
                        listElements[item].status = state;
                    }
                }
            };

            let listElements = groupInfo.toObject();
            let beforeCountElement = testCountElemStatus(listElements);

            for (let hex in listPossibleActions) {
                for (let key in listElements) {
                    if ((key === "id") || (key === "group_name") || (key === "date_register")) continue;

                    changeStatus({
                        id: listPossibleActions[hex].keyID,
                        state: listPossibleActions[hex].status,
                        listElements: listElements[key],
                        count: 0
                    });
                }
            }

            let afterCountElement = testCountElemStatus(listElements);

            if ((beforeCountElement.countIsTrue === afterCountElement.countIsTrue) && (beforeCountElement.countIsFalse === afterCountElement.countIsFalse)) {
                throw new MyError("group management warning", `Информация о группе '${groupName}' не изменялась, запись в базу данных не осуществляется.`);
            }

            return listElements;
        }).then((listElements) => {          
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelGroup, {
                    id: listElements.id,
                    update: listElements,
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });           
        }).then(() => {



            /**
 * Нужно сделать обновление session.user.information 
 * и объекта globalObject
 * 
 */


 

            //отправляем информационное сообщение о выполненной задаче
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Информация о группе пользователей '${groupName}' была успешно изменена.`
            });
        }).catch((err) => {
            if (err.name === "group management danger") {
                return showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message
                });
            } else if(err.name === "group management warning"){
                return showNotify({
                    socketIo: socketIo,
                    type: "warning",
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

function deleteGroup(socketIo, data) {
    const errMsg = "Невозможно удалить группу пользователей. Получены некорректные данные.";
    if(typeof data.arguments === "undefined"){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: errMsg,
        });

        writeLogFile("error", errMsg);

        return;
    }

    if(typeof data.arguments.groupName === "undefined"){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: errMsg,
        });

        writeLogFile("error", errMsg);

        return;
    }

    let groupName = data.arguments.groupName;

    //проверка авторизован ли пользователь
    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if(!authData.isAuthentication) {
                throw new MyError("group management", "Пользователь не авторизован.");
            }

            //может ли пользователь удалять группу пользователей
            if(!authData.document.groupSettings.management_groups.element_settings.delete.status) {
                throw new MyError("group management", "Невозможно удалить группу пользователей. Недостаточно прав на выполнение данного действия.");
            }

            if(!(/\b^[a-zA-Z0-9_-]+$\b/.test(groupName))) {
                throw new MyError("group management", "Невозможно удалить группу пользователей. Задано неверное имя группы.");
            }

            if(groupName.toLowerCase() === "administrator"){
                throw new MyError("group management", "Невозможно удалить группу пользователей с именем 'administrator'.");
            }
        }).then(() => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelGroup, {
                    query: { group_name: groupName },
                    select: { _id: 0, __v: 0, date_register: 0, group_name: 0 }
                }, (err, results) => {
                    if (err) reject(err);
                    if(!results){
                        reject(new MyError("group management", "Невозможно удалить группу пользователей. Группы с таким именем не существует."));
                    }

                    resolve();
                });
            });
        }).then(() => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(models.modelUser, { isMany: true, select: { 
                    _id: 0, 
                    login: 1,
                    group: 1,
                }}, (err, users) => {
                    if(err) reject(err);
                    else resolve(users);
                });
            });
        }).then((userList) => {
            for(let item of userList){
                if(item.group === groupName.toLowerCase()){
                    throw new MyError("group management", `Невозможно удалить группу пользователей. Есть пользователи входящие в состав группы '${groupName}'.`);
                }
            }
        }).then(() => {
            return new Promise((resolve,reject) => {
                mongodbQueryProcessor.queryDelete(models.modelGroup, { query: { group_name: groupName } }, err => {
                    if (err) reject(err);
                    resolve();
                });
            });
        }).then(() => {
            socketIo.emit("del selected group", JSON.stringify({
                groupName: groupName,
            }));

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Группа с именем '${groupName}' была успешно удалена.`,
            });
        }).catch((err) => {
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