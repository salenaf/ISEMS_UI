"use strict";

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
 *              "pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"execute","nffarf":9,"tsffarf":12900040,"nfd":8},{"tid":"2539c1a5c10abd7668444e085f6d1061","ctid":"83f905abcf8f30846b0783dc5a82dbe961857984","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":9,"tsffarf":12900040,"nfd":9},{"tid":"4b52190d116d33306aae803e98c55df6","ctid":"684fc2a6556f420500e7a7110d4167c7837d5c52","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":9,"tsffarf":12900040,"nfd":9},{"tid":"e8f74760b48cb0fc7245bc961e9472da","ctid":"6e389eb87441932eaa0211eecbc3b227db11197e","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":9,"tsffarf":12900040,"nfd":9},{"tid":"f4660fd55a110ba49cb8e0248fcee04e","ctid":"129c83ee78c2c7911df55f7472c62e0e86116b93","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"not executed","nffarf":9,"tsffarf":12900040,"nfd":0},{"tid":"dddc6613f9841be9a1ae37876afcdebf","ctid":"81fa34aee007e80f8cc4cf4cd6639402bfaf9910","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":9,"tsffarf":12900040,"nfd":9},{"tid":"ea77fb1ce73faebcba4d1b63fc42b0f3","ctid":"d54971e17de80a6344325c65efb0b92c7f33fe20","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":9,"tsffarf":12900040,"nfd":9},{"tid":"39fd569114cbccc8181c8a2f2ae9b3ff","ctid":"6140d02703f3368de8574d9cc4481954e9bbb519","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["192.168.13.67"],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":["56.36.9.33/25"],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":9,"tsffarf":12900040,"nfd":9},{"tid":"6fa8588ad1a87cb743aad566a378f40f","ctid":"72c0e6033b386aced48018f9375cd7e2d9deec7a","sid":1221,"pf":{"dt":{"s":1461715200,"e":1461801540},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":["192.168.13.11/24"],"src":[],"dst":[]}}},"fts":"complete","fdts":"not executed","nffarf":82,"tsffarf":5994165935,"nfd":0},{"tid":"8b30101186dd685689ab5711b569cd7a","ctid":"6ef921185646d4a2f4b7788c820500fb8da6bf32","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["59.66.3.4","192.168.13.100","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["122.33.2.43"],"dst":["188.123.33.6"]},"pt":{"any":[],"src":[],"dst":["53","80","110","8008"]},"nw":{"any":["56.36.9.33/25","78.100.3.66/26"],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":32,"tsffarf":2751729,"nfd":32},{"tid":"8e52fceb112744faf1443cf24a609c24","ctid":"1ec53cd8982edc6d1c83392e4e993f5c3cc98190","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["59.66.3.4","192.168.13.100","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["122.33.2.43"],"dst":["188.123.33.6"]},"pt":{"any":[],"src":[],"dst":["53","80","110","8008"]},"nw":{"any":["56.36.9.33/25","78.100.3.66/26"],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":32,"tsffarf":2751729,"nfd":32},{"tid":"fb7033262f52a10793187ebf6cb043b9","ctid":"8d1f18b91df3d85893f6b1507a174c2412260b28","sid":1221,"pf":{"dt":{"s":1560729600,"e":1560898800},"p":"tcp","f":{"ip":{"any":["59.66.3.4","192.168.13.100","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":["122.33.2.43"],"dst":["188.123.33.6"]},"pt":{"any":[],"src":[],"dst":["53","80","110","8008"]},"nw":{"any":["56.36.9.33/25","78.100.3.66/26"],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":32,"tsffarf":2751729,"nfd":32},{"tid":"a0e3a5f6a67b1d0f16ab323243cc8ec7","ctid":"c3b894868a6bf0906824ce9f7bcfd287e8df0e2a","sid":1221,"pf":{"dt":{"s":1461715200,"e":1461801540},"p":"tcp","f":{"ip":{"any":["192.168.156.12","45.78.9.10","95.174.101.95","87.240.131.213","185.26.182.93"],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":["192.168.13.11/24"],"src":[],"dst":[]}}},"fts":"complete","fdts":"not executed","nffarf":82,"tsffarf":5994165935,"nfd":0},{"tid":"7a8baffc0d2f9aac59386c6b5ee9e0c1","ctid":"4200dbf424cb85625fef89144ab7fd40d3a0dcf9","sid":1221,"pf":{"dt":{"s":1559740373,"e":1562418773},"p":"any","f":{"ip":{"any":["23.0.11.1","95.142.205.235"],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":4,"tsffarf":18000387,"nfd":4},{"tid":"4f83547b6ac05e5f7e487c7daa22533b","ctid":"4e2dab727f810362e61a9641ff85193d027855d7","sid":1221,"pf":{"dt":{"s":1560080736,"e":1562672736},"p":"any","f":{"ip":{"any":[],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":["8080","22","123"]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":32,"tsffarf":891876,"nfd":32},{"tid":"2642819815e846bc476825b9b0a9b99d","ctid":"5823f38c816d64ce39b5f47196b11106d748cf12","sid":1221,"pf":{"dt":{"s":1559904201,"e":1594723401},"p":"any","f":{"ip":{"any":["46.4.77.203"],"src":[],"dst":["204.51.94.155"]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":32,"tsffarf":4604490,"nfd":32},{"tid":"6fbf852028f740abcd2f14b586c18c62","ctid":"bc3a16fa4644b1c21aed82f2c1b29ea9cefbf97a","sid":1221,"pf":{"dt":{"s":1559991375,"e":1594724175},"p":"any","f":{"ip":{"any":[],"src":[],"dst":[]},"pt":{"any":["80"],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":32,"tsffarf":286453112,"nfd":32},{"tid":"dae61dedb8d512961cfc966702e5a0da","ctid":"68ad2c6a9d921a69f1e18a1300182638288c7b88","sid":1221,"pf":{"dt":{"s":1559473643,"e":1594724843},"p":"any","f":{"ip":{"any":[],"src":[],"dst":[]},"pt":{"any":["80"],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"not executed","nffarf":32,"tsffarf":286453112,"nfd":0},{"tid":"78bb2e6ecb9608ffccd54a0f1556733b","ctid":"16c2dac466d75e36b5c2061cddd35bfe6e6ed996","sid":1221,"pf":{"dt":{"s":1594558674,"e":1594731474},"p":"any","f":{"ip":{"any":["37.9.96.21"],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":25,"tsffarf":25380426,"nfd":25},{"tid":"7a7e303111d5ee8920e9ea4090ce8490","ctid":"dbd7dcf7861454abfcce503a73f2613d524e112c","sid":1221,"pf":{"dt":{"s":1594472487,"e":1594731687},"p":"any","f":{"ip":{"any":["95.173.144.169"],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":36,"tsffarf":114206817,"nfd":36},{"tid":"37906ffa4382a5ada9f43db8acc437c1","ctid":"b4cf0c23d0967a0d00ef76159fcb3084dd51c202","sid":1221,"pf":{"dt":{"s":1594561770,"e":1594734570},"p":"any","f":{"ip":{"any":["95.173.144.169"],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"complete","fdts":"complete","nffarf":72,"tsffarf":209811249,"nfd":72},{"tid":"8893f5e3d95d29b268672561368aaca9","ctid":"2f45b4cb9c5e02ad261183a5ec0db011d359628e","sid":1221,"pf":{"dt":{"s":1594598760,"e":1594735588},"p":"any","f":{"ip":{"any":["95.173.144.169"],"src":[],"dst":[]},"pt":{"any":[],"src":[],"dst":[]},"nw":{"any":[],"src":[],"dst":[]}}},"fts":"stop","fdts":"not executed","nffarf":34,"tsffarf":99955922,"nfd":0}]}}
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

    let funcName = " (func 'receivedListTasksDownloadFiles')";

    let listTasksDownloadFiles = globalObject.getData("tmpModuleNetworkInteraction", sessionId).listTasksDownloadFiles;
    if(typeof listTasksDownloadFiles === "undefined"){
        showNotify({
            socketIo: socketIo,
            type: "danger",
            message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.",
        });    

        return writeLogFile("error", "the 'listTasksDownloadFiles' property was not found in 'globalObject'"+funcName);
    }

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