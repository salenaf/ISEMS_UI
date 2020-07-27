"use strict";

const debug = require("debug")("haprlt");

const showNotify = require("../../libs/showNotify");
const writeLogFile = require("../../libs/writeLogFile");
const globalObject = require("../../configure/globalObject");

const MAX_CHUNK_SIZE = 10;

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
    debug("func 'receivedListTasksDownloadFiles', START...");
   
    let funcName = " (func 'receivedListTasksDownloadFiles')";

    if(!globalObject.getData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles")){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
        });    

        return writeLogFile("error", "the 'listTasksDownloadFiles' property was not found in 'globalObject'"+funcName);

    }

    let tasksDownloadFiles = globalObject.getData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles");

    if((typeof tasksDownloadFiles.taskID === "undefined") || (tasksDownloadFiles.taskID !== data.taskID)){
    //если ID задачи не совпадают создаем новую запись
        globalObject.setData("tmpModuleNetworkInteraction", sessionId, "tasksDownloadFiles", { 
            taskID: data.taskID,                 
            status: data.options.s,
            numFound: data.options.tntf,
            paginationOptions: {
                chunkSize: data.options.p.cs,
                chunkNumber: data.options.p.cn,
                chunkCurrentNumber: data.options.p.ccn
            },
            listTasksDownloadFiles: data.options.slft,
        });
    } else {
        tasksDownloadFiles.listTasksDownloadFiles.push(data.options.slft);
    }

    let numFullChunks = 1;
    if(data.options.tntf > MAX_CHUNK_SIZE){
        numFullChunks = Math.ceil(data.options.tntf/MAX_CHUNK_SIZE);
    }

    //отправляем в UI если это первый сегмент
    if(data.options.p.ccn === 1){
        socketIo.emit("module NI API", { 
            "type": "get list tasks files not downloaded",
            "taskID": data.taskID,
            "options": {
                p: {
                    cs: MAX_CHUNK_SIZE, //размер части
                    cn: numFullChunks, //всего частей
                    ccn: 1, //номер текущей части
                },
                tntf: data.options.tntf,
                slft: require("../../libs/helpers/helpersFunc").modifyListFoundTasks(data.options.slft.slice(0, MAX_CHUNK_SIZE)),
            }
        });    
    }
};