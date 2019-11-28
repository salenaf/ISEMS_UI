/*
 * Глобальный объект для промежуточного хрнения данных
 * содержит:
 *
 * descriptionDB - дискрипторы соединения с СУБД
 * descriptionAPI - дискрипторы соединения с API
 *
 * users - информацию по пользователям
 * sources - информацию об источниках (в том числе отслеживание 'свежесть' полученных от источников данных)
 * 
 * Весрия 0.1, дата релиза 10.01.2019
 * */

"use strict";

const EventEmitter = require("events");

class SocketioEventResponse extends EventEmitter {}

class GlobalObject {
    constructor() {
        this.obj = {
            "users": {},
            "sources": {},
            "commonSettings": {},
            "descriptionDB": {},
            "descriptionAPI": {},
            "socketioEventResponse": new SocketioEventResponse()
        };
    }

    _checkKeys(type) {
        if (type === null) return true;
        if (typeof this.obj[type] === "undefined") return true;

        return false;
    }

    /**
     * возвращает объект EventEmitter предназначенный для передачи ответов через socketio
     */
    getEventSocketioResponse() {
        return this.obj.socketioEventResponse;
    }

    /**
     * добавляет данные по выбранному типу, ID группы и ключу
     * @param type тип модифицированного объекта ('descriptionDB', 'descriptionAPI', 'users', 'sources')
     * @param group группа (например если это 'descriptionDB', то 'MongoDB', 'ClickhouseDB' и т.д.)
     * @param key имя устанавливаемого поля
     * @param value значение устанавливаемого поля
     * 
     * пример:
     *    globalObject.setData('descriptionDB', MongoDB, {
     *        'connection': <дискриптор соединения>,
     *        'connectionTimestamp': <время установления соединения (формат unix)>
     *        'userName': <имя пользователя под которым оно установлено>
     *    });
     */
    setData(type, group, key = null, value = null) {
        if (this._checkKeys(type)) return false;
        if (typeof group === "undefined") return false;
        if (key === null) return false;

        if ((value === null) && (typeof key === "object")) {
            this.obj[type][group] = key;

            return true;
        }

        this.obj[type][group][key] = value;

        return true;
    }

    /**
     * получить данные по выбранным типу, группе и ключу
     * причем группа и ключ являются не обязательными полями
     * @param {*} type 
     * @param {*} group 
     * @param {*} key 
     */
    getData(type, group = null, key = null) {
        if (this._checkKeys(type)) return null;
        if (group === null) return this.obj[type];
        if (typeof this.obj[type][group] === "undefined") return null;
        if (key === null) return this.obj[type][group];

        return (typeof this.obj[type][group][key] === "undefined") ? null : this.obj[type][group][key];
    }

    /**
     * модифицирует информацию по выбранному типу 
     * @param type тип модифицированного объекта ('sources', 'processingTasks', 'downloadFilesTmp', 'writeStreamLinks')
     * @param group группа (может быть ID задачи  или источника)
     * @param arrayData массив с изменяемыми данными
     * 
     * пример:
     *    globalObject.modifyData('processingType', taskIndex, [
     *          ['status', 'in line'],
     *          ['timestampModify', +new Date()]
     *     ]);
     */
    modifyData(type, group, arrayData) {
        if (this._checkKeys(type)) return false;
        if (typeof group === "undefined") return false;

        arrayData.forEach(element => {
            if (Array.isArray(element) && (element.length === 2)) {
                if ((typeof this.obj[type][group] === "undefined") || (typeof this.obj[type][group][element[0]] === "undefined")) return;

                this.obj[type][group][element[0]] = element[1];
            }
        });

        return true;
    }

    //удалить данные по выбранному типу и группе
    deleteData(type, group) {
        if (this._checkKeys(type)) return false;

        delete this.obj[type][group];

        return true;
    }
}

let globalObject;

module.exports = createObject();

function createObject() {
    if (globalObject instanceof GlobalObject) return globalObject;

    globalObject = new GlobalObject();

    return globalObject;
}