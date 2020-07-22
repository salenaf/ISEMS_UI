"use strict";

const debug = require("debug")("haprlt");

const showNotify = require("../../libs/showNotify");
const writeLogFile = require("../../libs/writeLogFile");
const globalObject = require("../../configure/globalObject");

/**
 * Обработчик модуля сетевого взаимодействия осуществляющий обработку
 * принятого списка задач файлы по которым не выгружались
 * 
 * @param {*} socketIo - дескриптор socketIo соединения
 * @param {*} data - полученные, от модуля сетевого взаимодействия, данные
 * 
 * Так как список задач файлы по которым не выгружались может
 * быть СЕГМЕНТИРОВАН и приходить в несколько частей нужно его 
 * временно сложить в память, а потом вытаскивать по мере запроса.
 * 
 * Исключение составляет первая или единственная часть которая
 * автоматически отправляется в UI
 */
module.exports.receivedListTasksDownloadFiles = function(socketIo, data, sessionId){
    /**
 * data содержит примерно следующую конструкцию
 * 
 * {
 * "instruction":"processing information search task",
 * "taskID":"74ca59d3e44151fde8ffa5c9acd6118420c6278a",
 * "options":{
 *      "tidapp":"b512df53c1989d633778585d6ef83831aafed239",
 *      "s":"complete",
 *      "tntf":23,
 *      "p":{
 *          "cs":100,
 *          "cn":1,
 *          "ccn":1
 *      },
 *      "slft":[
 *          {
 *              "tid":"483bbcc6adeab487cd9f8075697a5a74",
 *              "ctid":"1c8a01d8b0b31cb52c3e4d6e025c0b468cbac6fd",
 *              "sid":1221,
 *              "pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"execute","nffarf":9,"tsffarf":12900040,"nfd":9},
 *          {
 *              "tid":"84a41784eb71e77e8fb7d2f0ddfcbf00",
 *              "ctid":"b58cc28ae2e61d191e797cd09d55b0365da0866a",
 *              "sid":1221,
 *              "pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"execute","nffarf":9,"tsffarf":12900040,"nfd":8},
 *          }
 */

    /**
 * 1. Получили данные от модуля сет. взаимодействия (список задач файлы по которым
 * не выгружались). Это событие может происходить несколько раз подрят, так как
 * список может быть сегментирован.
 * 2. По taskID (data.taskID) в globalObject.tasks ищем sessionId в свойстве
 * userSessionID
 * 3. По userSessionID ищем в globalObject.tmp запись в виде массива, если нет
 * создаем новую, если есть дописываем в конец массива. 
 * 4. Отправляем первую или единственную запись в UI.
 * 5. Если запись в массиве единственная, удаляем ее, она скорее всего
 * не понадобится (а если понадобится будет новый запрос). Понадобится она может только
 * в том случае если у нас на странице будет пагинатор.
 */

    debug("func 'receivedListTasksDownloadFiles', START...");

    let funcName = " (func 'receivedListTasksDownloadFiles')";

    /*
Создать tmpModuleNetworkInteraction.<sessionId>.tasksDownloadFiles при авторизации
пользователя (или проверки авторизации при востановлении уч. данных при перезагрузки
приложения). 
Удалить tmpModuleNetworkInteraction.<sessionId>.tasksDownloadFiles при пользователе logout
*/

    let tmpModuleNetworkInteraction = globalObject.getData("tmpModuleNetworkInteraction", sessionId);
    
    console.log("===================");
    console.log(tmpModuleNetworkInteraction);
    
    if((tmpModuleNetworkInteraction === null) || (typeof tmpModuleNetworkInteraction.tasksDownloadFiles === "undefined")){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
        });    

        return writeLogFile("error", "the 'listTasksDownloadFiles' property was not found in 'globalObject'"+funcName);
    }
    //        globalObject.setData("tmpModuleNetworkInteraction", sessionId)
    
    let tasksDownloadFiles = tmpModuleNetworkInteraction.tasksDownloadFiles;
    
    console.log("*******************");
    console.log(tasksDownloadFiles);
    console.log(tasksDownloadFiles.listTasksDownloadFiles);
    console.log("*******************");

    if((typeof tasksDownloadFiles.listTasksDownloadFiles !== "undefined") && (tasksDownloadFiles.listTasksDownloadFiles.length > 0)){
        //если запись уже есть то просто дописываем в конец
        tasksDownloadFiles.listTasksDownloadFiles.push(data.options);

        globalObject.setData("tmpModuleNetworkInteraction", sessionId, tasksDownloadFiles);
    } else {
        //если записи еще нет
        if(data.options.p.cn > 1){
            //если сегментов больше одного создаем новую запись
            globalObject.setData("tmpModuleNetworkInteraction", sessionId, tasksDownloadFiles, { 
                taskID: data.taskID,                 
                status: data.options.s,
                numFound: data.options.tntf,
                paginationOptions: {
                    chunkSize: data.options.p.cs,
                    chunkNumber: data.options.p.cn,
                    chunkCurrentNumber: data.options.p.cnn
                },
                listTasksDownloadFiles: [],
            });
        }
    }

    /**
 * Нужно сделать что бы в списке было краткое название источника
 * это можно сделать через globalObject.setData("sources")
 * и сформировать новый список options
 */

    //отправляем информацию в UI
    socketIo.emit("module NI API", { 
        "type": "get list tasks files not downloaded",
        "taskID": data.taskID,
        "options": data.options,
    });    

    /*
    
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        Это не доделанное. Доделать и протестировать
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

if(listTasksDownloadFiles.length > 0){
        //если запись уже есть то просто дописываем в конец
        listTasksDownloadFiles.push({ taskID: data.taskID, options: data.options });
globalObject.setData("tmpModuleNetworkInteraction", sessionId, listTasksDownloadFiles);
} else {
        //если записи еще нет
    
        if(data.options.p.cn > 1){
            //если сегментов больше одного создаем новую запись
            globalObject.setData("tmp", "moduleNetworkInteraction", sessionId, { taskID: data.taskID, options: data.options });
        }
        globalObject.setData("tmpModuleNetworkInteraction", sessionId, {
            listTasksDownloadFiles: {},
            listFoundTasks: {},
        });
        //отправляем информацию в UI
        socketIo.emit("module NI API", { 
            "type": "get list tasks files not downloaded",
            "taskID": data.taskID,
            "options": data.options,
        });    
}*/

    /*    if(globalObject.hasData("tmpModuleNetworkInteraction", sessionId)){
        //если запись уже есть то просто дописываем в конец
        let tmpList = globalObject.getData("tmp", "moduleNetworkInteraction", sessionId);
        tmpList.push({ taskID: data.taskID, options: data.options });
        globalObject.setData("tmp", "moduleNetworkInteraction", sessionId, tmpList);
    } else {
        //если записи еще нет
    
        if(data.options.p.cn > 1){
            //если сегментов больше одного создаем новую запись
            globalObject.setData("tmp", "moduleNetworkInteraction", sessionId, { taskID: data.taskID, options: data.options });
        }

        //отправляем информацию в UI
        socketIo.emit("module NI API", { 
            "type": "get list tasks files not downloaded",
            "taskID": data.taskID,
            "options": data.options,
        });
    }*/

    /**
 *      !!!!
 *  Протестировать по сегментам
 * пока приходит только один сегмент (надо на множестве)
 * 
 * Проблемма в том что один и тот же объект будет использоваться для хранения 
 * как списка задач по которым файлы не выгружались, так и списка задач
 * полученного в результате поиска. Страница для предоставления этой
 * информации фактически одна и таже, только разные вкладки. При переходе из вкладки
 * поиска во вкладку загрузка файлов данные будут перезаписаны, что не допустимо.
 * 
 * Кстати надо не забыть сделать обработку ОСТАНОВА выполнения задачи по 
 * скачиванию файлов
 * 
 */

};