"use strict";

const EventEmitter = require("events");

class SocketioEventResponse extends EventEmitter {}

/**
 * Глобальный объект для промежуточного хрнения данных
 * 
 *   {
 *       временные данные
 *       здесь хранится информация о задачах фильтрации и выгрузки
 *       файлов полученная из модуля сетевого взаимодействия
 *       доступ по sessionId пользователя (это все для пагинатора)
 *       tmpModuleNetworkInteraction: {
 *          <sessionId>: {
 *              //информация о списках задач по скачиванию файлов
 *              tasksDownloadFiles: {
 *                  taskID: STRING,                 
 *                  status: STRING,
 *                  numFound: INT, //сколько всего найдено
 *                  paginationOptions: { параметры разбиения частей
 *			            chunkSize: INT размер сегмента (кол-во задач в сегменте)
 *			            chunkNumber: INT общее количество сегментов
 *			            chunkCurrentNumber: INT номер текущего фрагмента
 *                  }
 *                  listTasksDownloadFiles: []
 *              },
 *              //информация о списках задач не отмеченных пользователем как завершенные
 *              unresolvedTask: {
 *                  taskID: STRING,                 
 *                  status: STRING,
 *                  numFound: INT, //сколько всего найдено
 *                  paginationOptions: { параметры разбиения частей
 *			            chunkSize: INT размер сегмента (кол-во задач в сегменте)
 *			            chunkNumber: INT общее количество сегментов
 *			            chunkCurrentNumber: INT номер текущего фрагмента
 *                  }
 *                  listUnresolvedTask: [] 
 *              },
 *              resultFoundTasks: {},
 *          }
 *       },
 *       выполняемые задачи для генерирования событий основываясь на 
 *       полученном от модуля ID
 *       tasks: {
 *          <task ID>: {
 *              eventName: название события в UI
 *          },
 *       },
 *       параметры пользователя все из БД
 *       users: {
 *          userLogin: логин,
 *          userName: имя,
 *          userGroup: группа,
 *          groupSettings: групповые настройки пользователя,
 *          userSettings: общие настройки пользователя,
 *       },
 *       параметры истчников
 *       sources: {
 *          shortName: название источника,
 *          description: описание,
 *          connectStatus: статус соединения,
 *          connectTime: время соединения,
 *          id: id источника,
 *       },
 * 
 *       дескрипторы соединения с API
 *       descriptionAPI: {
 *           networkInteraction: {
 *               connection: object,
 *               connectionEstablished: bool }}
 *   } 
 */
class GlobalObject {
    constructor() {
        this.obj = {
            "tasks": {},
            "users": {},
            "sources": {},
            "commonSettings": {},
            "descriptionDB": {},
            "descriptionAPI": {},
            "socketioEventResponse": new SocketioEventResponse(),
            "tmpModuleNetworkInteraction": {},
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
        if (this._checkKeys(type)) {
            return false;
        }
        if (typeof group === "undefined") {
            return false;
        }
        if (key === null) {
            return false;
        }

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
     * 
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
    * проверить наличие значений
    * 
    * @param {*} type 
    * @param {*} group 
    * @param {*} key 
    */    
    hasData(type, group = null, key = null){
        if (this._checkKeys(type)) {
            return false;
        } else if (group === null) {
            return true;
        } else if (group !== null && key === null){
            return (typeof this.obj[type][group] !== "undefined");
        } else {
            return (typeof this.obj[type][group][key] !== "undefined");
        }
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

        arrayData.forEach((element) => {
            if (Array.isArray(element) && (element.length === 2)) {
                if ((typeof this.obj[type][group] === "undefined") || (typeof this.obj[type][group][element[0]] === "undefined")) return;

                this.obj[type][group][element[0]] = element[1];
            }
        });

        return true;
    }

    //удалить данные по выбранному типу и группе
    deleteData(type, group, key = null) {
        if (this._checkKeys(type)) return false;
        if (key === null) {
            delete this.obj[type][group];

            return true;
        }
        if (!Array.isArray(this.obj[type][group])){
            delete this.obj[type][group][key];
        }

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