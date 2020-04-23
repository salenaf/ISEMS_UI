/**
 * Модуль является посредником между элементами приложения и СУБД (в данном случае MongoDB). 
 * Данный модуль является оберткой для всех запросов к СУБД и возвращает результат запроса после его 
 * успешной обработки СУБД или исключение. 
 * 
 * Версия 0.1, дата релиза 10.01.2019
 */

"use strict";

const debug = require("debug")("mongodbQueryProcessor");

const globalObject = require("../configure/globalObject");

class QueryProcessor {
    constructor() {
        this.connect = globalObject.getData("descriptionDB", "MongoDB", "connection");
    }

    /**
     * Поиск элементов в коллекции
     * 
     * @param {*} mongooseModel имя модели (таблица)
     * @param {*} settingsQuery параметры запросов 
     *                          { id: <ID элемента> (может быть object, number, string или undefined),
     *                            isMany: <true/false/undefined>,                           
     *                            query: <object / undefined>,
     *                            select: <object / string / undefined>,   
     *                            options: <object / undefined> }
     * 
     * по "select" подробнее смотреть в Query.prototype.select() Mongoose
     * по "options" подробнее смотреть в Query.prototype.setOptions() Mongoose
     * @param {*} callback функция обратного вызова возвращает error или null и объект документа
     *
     * Модели:
     *      Model.find()
     *      Model.findById()
     *      Model.findOne()
     */
    querySelect(mongooseModel, settingsQuery, callback) {
        let { id = null, select = "", options = {}, query = {}, isMany = false } = settingsQuery;

        debug("--- function \"querySelect\"");
        debug("settingsQuery");
        debug(settingsQuery);

        debug(`id = ${id}`);
        debug("query:");
        debug(query);
        debug(`select: ${select}`);
        debug("options");
        debug(options);

        if (id !== null) {
            mongooseModel.findById(id, select, options, (err, doc) => {
                if (err) callback(err);
                else callback(null, doc);
            });
        } else {
            let commandFind = (isMany) ? "find" : "findOne";

            debug(`commandFind "${commandFind}"`);

            mongooseModel[commandFind](query, select, options, (err, docs) => {
                if (err) callback(err);
                else callback(null, docs);
            });
        }
    }

    /**
     * Создание новой модели документа на основе его схемы
     * 
     * @param {*} mongooseModel имя модели (таблица)
     * @param {*} settingsQuery параметры запроса
     *                          { document: {} }
     * @param {*} callback функция обратного вызова возвращает error или null
     */
    queryCreate(mongooseModel, settingsQuery, callback) {
        new mongooseModel(settingsQuery.document).save(err => {
            if (err) callback(err);
            else callback(null);
        });
    }

    /**
     * Вставка новых элементов
     * 
     * @param {*} mongooseModel 
     * @param {*} documents (array|object) 
     * @param {*} callback 
     */
    queryInsertMany(mongooseModel, documents, callback) {
        mongooseModel.insertMany(
            documents, 
            { ordered: false }, 
            (err, doc) => {
                if (err) callback(err);
                else callback(null, doc);
            });
    }

    /**
     * Обновление элементов коллекции
     * 
     * @param {*} mongooseModel имя модели (таблица)
     * @param {*} settingsQuery параметры запросов 
     *                          { id: <ID элемента> (может быть object, number, string или undefined),
     *                            isMany: <true/false/undefined>,                           
     *                            query: <object / undefined>,
     *                            update: <object>
     *                            select: <object / string / undefined>,   
     *                            options: <object / undefined> }
     * 
     * по "select" подробнее смотреть в Query.prototype.select() Mongoose
     * по "options" подробнее смотреть в Query.prototype.setOptions() Mongoose
     * @param {*} callback 
     * 
     * Модели:
     *      Model.updateMany()
     *      Model.findByIdAndUpdate()
     *      Model.findOneAndUpdate()
     */
    queryUpdate(mongooseModel, settingsQuery, callback) {
        let {
            id = null,
            select = "",
            query = {},
            update = {},
            isMany = false
        } = settingsQuery;

        debug("--- function \"querySelect\"");
        debug("settingsQuery");
        debug(settingsQuery);

        debug(`id = ${id}`);
        debug("query:");
        debug(query);
        debug(`select: ${select}`);

        if (id !== null) {
            mongooseModel.findByIdAndUpdate(id, update, select, err => {
                if (err) callback(err);
                else callback(null);
            });
        } else {
            let commandFind = (isMany) ? "updateMany" : "findOneAndUpdate";

            mongooseModel[commandFind](query, update, select, err => {
                if (err) callback(err);
                else callback(null);
            });
        }
    }

    /**
     * Удаление элементов коллекции
     * 
     * @param {*} mongooseModel имя модели (таблица)
     * @param {*} settingsQuery параметры запросов 
     *                          { id: <ID элемента> (может быть object, number, string или undefined),
     *                            isMany: <true/false/undefined>,
     *                            query: <объект запроса / undefined> }
     * @param {*} callback функция обратного вызова возвращает error или null
     * 
     * Модели:
     *      Model.deleteOne() удаляет один элемент
     *      Model.deleteMany() удаляет все найденные элементы
     *      Model.findByIdAndRemove() удаляет элемент по ID И ВОЗВРАЩАЕТ ЕГО
     *      Model.findOneAndRemove() удаляет элемент И ВОЗВРАЩАЕТ ЕГО
     */
    queryDelete(mongooseModel, settingsQuery, callback) {
        if (typeof settingsQuery !== "object") return callback(new Error("parameter \"settingsQuery\" is not an object"));

        let queryIsExist = typeof settingsQuery.query === "undefined";
        let idIsExist = typeof settingsQuery.id === "undefined";
        let manyOrOneIsExist = typeof settingsQuery.isMany === "undefined";

        //проверяем наличие необходимых параметров
        if (queryIsExist && idIsExist && manyOrOneIsExist) return callback(new Error("error in database query, missing one or more key parameters"));

        //поиск по ID, удаление и возврат найденного элемента
        if (!idIsExist) {
            mongooseModel.findByIdAndRemove(settingsQuery.id, callback);

            return;
        }

        //проверяем наличие параметров поиска
        if (queryIsExist || (typeof settingsQuery.query !== "object")) return callback(new Error("error in database query, missing parameter query"));

        //поиск по элементу, его удаление и его возврат
        if (manyOrOneIsExist) {
            mongooseModel.findOneAndRemove(settingsQuery.query, callback);

            return;
        }

        let typeDelete = (manyOrOneIsExist) ? "deleteMany" : "deleteOne";

        mongooseModel[typeDelete](settingsQuery.query, callback);
    }

    /**
     * Специальные запросы к коллекциям
     * 
     * @param {*} mongooseModel 
     * @param {*} settingsQuery 
     * @param {*} specialSettings
     * @param {*} callback 
     */
    querySpecial(mongooseModel, settingsQuery, specialSettings, callback) {

    }
}

let queryProcessor;

module.exports = createObject();

function createObject() {
    if (queryProcessor instanceof QueryProcessor) return queryProcessor;

    queryProcessor = new QueryProcessor();
    return queryProcessor;
}