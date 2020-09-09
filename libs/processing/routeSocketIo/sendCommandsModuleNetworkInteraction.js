"use strict";

const debug = require("debug")("scmni");

const MyError = require("../../helpers/myError");
const helpersFunc = require("../../helpers/helpersFunc");
const getSessionId = require("../../helpers/getSessionId");
const globalObject = require("../../../configure/globalObject");

/** ---  УПРАВЛЕНИЕ ИСТОЧНИКАМИ --- **/

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками.
  * 
  * Выполняет добавление новых источников в базу данных модуля. 
  * 
  * @param {*} sourceList - список источников
  */
module.exports.sourceManagementsAdd = function(sourceList){
    return new Promise((resolve, reject) => {
        process.nextTick(() => {          
            if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let list = sourceList.map((item) => {
                let sourceID = +(item.source_id);
                let architecture = (item.source_settings.type_architecture_client_server === "server") ? true: false;
                let telemetry = (item.source_settings.transmission_telemetry === "on");

                sources.push(sourceID);

                return {
                    id: sourceID,
                    at: "add", 
                    arg: {
                        ip: item.network_settings.ipaddress,
                        t: item.network_settings.token_id,
                        sn: item.short_name,
                        d: item.description,
                        s: {
                            as: architecture,
                            p: +(item.network_settings.port),
                            et: telemetry,
                            mcpf: +(item.source_settings.maximum_number_simultaneous_filtering_processes),
                            sf: item.source_settings.list_directories_with_file_network_traffic,
                            tan: item.source_settings.type_channel_layer_protocol,
                        },				
                    }
                };});

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            
            if(conn !== null){
                let hex = helpersFunc.getRandomHex();

                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: hex,
                    options: { sl: list },
                });
            }    

            resolve();
        });
    });
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками.
  * 
  * Выполняет обновление информации об источнике в базе данных модуля. 
  * 
  * @param {*} sourceList - список источников
  */
module.exports.sourceManagementsUpdate = function(sourceList){
    return new Promise((resolve, reject) => {
        process.nextTick(() => {          
            if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let list = sourceList.map((item) => {
                let sourceID = +(item.source_id);
                let architecture = (item.source_settings.type_architecture_client_server === "server") ? true: false;
                let telemetry = (item.source_settings.transmission_telemetry === "on");

                sources.push(sourceID);

                return {
                    id: sourceID,
                    at: "update", 
                    arg: {
                        ip: item.network_settings.ipaddress,
                        t: item.network_settings.token_id,
                        sn: item.short_name,
                        d: item.description,
                        s: {
                            as: architecture,
                            p: +(item.network_settings.port),
                            et: telemetry,
                            mcpf: +(item.source_settings.maximum_number_simultaneous_filtering_processes),
                            sf: item.source_settings.list_directories_with_file_network_traffic,
                            tan: item.source_settings.type_channel_layer_protocol,
                        },				
                    }
                };});

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            
            if(conn !== null){
                let hex = helpersFunc.getRandomHex();

                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: hex,
                    options: { sl: list },
                });
            }    

            resolve();
        });
    });
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками.
  * 
  * Выполняет удаление источников из базы данных модуля. 
  * 
  * @param {*} sourceList - список источников
  */
module.exports.sourceManagementsDel = function(sourceList){
    return new Promise((resolve, reject) => {
        process.nextTick(() => {          
            if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let list = sourceList.map((item) => {
                console.log(item);

                let sourceID = +(item.source);
                sources.push(sourceID);

                return {
                    id: sourceID,
                    at: "delete", 
                    arg: {},				
                };
            });

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            
            if(conn !== null){
                let hex = helpersFunc.getRandomHex();

                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: hex,
                    options: { sl: list },
                });
            }    

            resolve();
        });
    });    
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками.
  * 
  * Выполняет удаление источников из базы данных модуля. 
  * 
  * @param {*} sourceList - список источников
  */
module.exports.sourceManagementsReconnect = function(sourceList){
    return new Promise((resolve, reject) => {
        process.nextTick(() => {          
            if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                return reject(new MyError("management network interaction", "Передача списка источников модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let sources = [];
            let sourceNotFound = [];
            let sourceNotConnection = [];

            sourceList.forEach((source) => {
                let sourceInfo = globalObject.getData("sources", source);
                if(sourceInfo === null){
                    sourceNotFound.push(source);
                } else if(!sourceInfo.connectStatus){
                    sourceNotConnection.push(source);
                } else {
                    sources.push({
                        id: source,
                        at: "reconnect", 
                        arg: {},
                    });
                }
            });

            if(sourceNotFound.length > 0){
                let textOne = (sourceNotFound.length > 1) ? "Источники": "Источник";
                let textTwo = (sourceNotFound.length > 1) ? "найдены": "найден";

                return reject(new MyError("management network interaction", `${textOne} с идентификатором ${sourceNotFound.join(",")} не ${textTwo}.`));
            }

            if(sourceNotConnection.length > 0){
                let textOne = (sourceNotConnection.length > 1) ? "Источники": "Источник";
                let textTwo = (sourceNotConnection.length > 1) ? "подключены": "подключен";

                return reject(new MyError("management network interaction", `${textOne} с идентификатором ${sourceNotConnection.join(",")} не ${textTwo}.`));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");
            
            if(conn !== null){
                let hex = helpersFunc.getRandomHex();

                conn.sendMessage({
                    msgType: "command",
                    msgSection: "source control",
                    msgInstruction: "performing an action",
                    taskID: hex,
                    options: { sl: sources },
                });
            }

            resolve();
        });
    });    
};

/** ---  УПРАВЛЕНИЕ ЗАДАЧАМИ ПО ФИЛЬТРАЦИИ СЕТЕВОГО ТРАФИКА --- **/

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление задачами по фильтрации сетевого трафика.
  *  
  * Осуществляет запуск задачи по фильтрации сет. трафика. 
  * 
  * @param {*} filteringParameters - параметры фильтрации
  * @param {*} userLogin - логин пользователя
  * @param {*} userName - имя пользователя
  */
module.exports.managementTaskFilteringStart = function(filteringParameters, userLogin, userName){
    console.log("func 'managementTaskFilteringStart'");
    console.log(filteringParameters);
    console.log(`user name: '${userName}', user login '${userLogin}'`);
 
    return new Promise((resolve, reject) => {
        process.nextTick(() => {          
            if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            //проверяем существование источника и статус его соединения
            let sourceInfo = globalObject.getData("sources", filteringParameters.source);
            if(sourceInfo === null){
                return reject(new MyError("management network interaction", `Источник с идентификатором ${filteringParameters.source} не найден.`));

            } 
            if(!sourceInfo.connectStatus){
                return reject(new MyError("management network interaction", `Источник с идентификатором ${filteringParameters.source} не подключен.`));                                        
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");           
            if(conn !== null){
                let hex = helpersFunc.getRandomHex();

                let tmp = {
                    msgType: "command",
                    msgSection: "filtration control",
                    msgInstruction: "to start filtering",
                    taskID: hex,
                    options: { 
                        id: filteringParameters.source,
                        un: userName,
                        dt: {
                            s: filteringParameters.dateTime.start,
                            e: filteringParameters.dateTime.end,
                        },
                        p: filteringParameters.networkProtocol,
                        f: filteringParameters.inputValue,
                    },
                };

                console.log("---------- forming Request ----------");
                console.log(JSON.stringify(tmp));
            
                conn.sendMessage(tmp);
            }    

            resolve();
        });
    }); 
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление задачами по фильтрации сетевого трафика.
  *  
  * Осуществляет останов задачи по фильтрации сет. трафика. 
  * 
  * @param {*} taskID - ID останавливаемой задачи
  * @param {*} sourceID - ID источника
  */
module.exports.managementTaskFilteringStop = function(taskID, sourceID){
    console.log("func 'managementTaskFilteringStop', START...");
    console.log(`stop task ID: ${taskID}`);

    return new Promise((resolve, reject) => {
        process.nextTick(() => {          
            if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            //проверяем существование источника и статус его соединения
            let sourceInfo = globalObject.getData("sources", sourceID);
            if(sourceInfo === null){
                return reject(new MyError("management network interaction", `Источник с идентификатором ${sourceID} не найден.`));

            } 
            if(!sourceInfo.connectStatus){
                return reject(new MyError("management network interaction", `Источник с идентификатором ${sourceID} не подключен.`));                                        
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");           
            if(conn !== null){
                let tmp = {
                    msgType: "command",
                    msgSection: "filtration control",
                    msgInstruction: "to cancel filtering",
                    taskID: taskID,
                    options: {},
                };

                console.log("---------- forming Request ----------");
                console.log(JSON.stringify(tmp));
            
                conn.sendMessage(tmp);
            }    

            resolve();
        });
    }); 
};

/** ---  УПРАВЛЕНИЕ ЗАПРОСАМИ ДЛЯ ПОЛУЧЕНИЯ ИНФОРМАЦИИ О ЗАДАЧАХ --- **/

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * запрос всей информации о задаче по ее ID.
  *  
  * @param {*} taskID - ID задачи по которой нужно найти информацию
  */
module.exports.managementRequestShowTaskAllInfo = function(taskID){
    console.log("func 'managementRequestShowTaskAllInfo'");
    console.log(`ID задачи по которой нужно найти информацию '${taskID}'`);
 
    return new Promise((resolve, reject) => {
        process.nextTick(() => {          
            if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
                return reject(new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен."));
            }

            let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");           
            if(conn !== null){
                let tmp = {
                    msgType: "command",
                    msgSection: "information search control",
                    msgInstruction: "get all information by task ID",
                    taskID: helpersFunc.getRandomHex(),
                    options: { rtid: taskID }
                };

                console.log("---------- forming Request ----------");
                console.log(JSON.stringify(tmp));
            
                conn.sendMessage(tmp);
            }    

            resolve();
        });
    }); 
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * запрос всего списка задач 
  * 
  * @param {*} socketIo 
  */
module.exports.managementRequestGetListAllTasks = function(socketIo){
    debug("func 'managementRequestGetListAllTasks', START...");

    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");           
        if(conn !== null){
            let hex = helpersFunc.getRandomHex();

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "list all tasks",
                userSessionID: sessionId,
            });

            let tmp = {
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: {
                    sriga: true, //отмечаем что задача выполняется в автоматическом режиме 
                },
            };
        
            debug("send message ---> to network interaction");
            debug(tmp);

            conn.sendMessage(tmp);
        }    
    });
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * запрос списка задач по которым не были выгружены все файлы.
  *  
  * @param {*} socketIo 
  */
module.exports.managementRequestGetListTasksDownloadFiles = function(socketIo){
    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");           
        if(conn !== null){
            let hex = helpersFunc.getRandomHex();

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "list tasks which need to download files",
                userSessionID: sessionId,
            });

            let tmp = {
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: {
                    sriga: true, //отмечаем что задача выполняется в автоматическом режиме
                    sft: "complete",
                    cpafid: true,
                    afid: false,
                    iaf: {
                        fif: true,
                    } 
                },
            };
        
            conn.sendMessage(tmp);
        }    
    });
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * запрос списка задач, не отмеченных пользователем как завершенные
  * 
  * @param {*} socketIo 
  */
module.exports.managementRequestGetListUnresolvedTasks = function(socketIo){
    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");           
        if(conn !== null){
            let hex = helpersFunc.getRandomHex();

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "list unresolved tasks",
                userSessionID: sessionId,
            });

            let tmp = {
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: {
                    sriga: true, //отмечаем что задача выполняется в автоматическом режиме
                    sft: "complete",
                    cptp: true,
                    tp: false,
                    cpfid: true,
                    fid: true,
                    iaf: {
                        fif: true,
                    } 
                },
            };
        
            conn.sendMessage(tmp);
        }    
    });
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * запрос списка задач по заданным критериям поиска
  * 
  * @param {*} socketIo 
  * @param {*} data 
  */
module.exports.managementRequestSearchInformationAboutTasks = function(socketIo, data){
    return new Promise((resolve, reject) => {
        //получаем сессию пользователя что бы потом с помощью нее хранить и искать 
        // временную информацию в globalObject.tmp
        getSessionId("socketIo", socketIo, (err, sessionId) => {
            if (err) reject(err);
            else resolve(sessionId);
        });
    }).then((sessionId) => {
        if(!globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")){               
            throw new MyError("management network interaction", "Передача задачи модулю сетевого взаимодействия невозможна, модуль не подключен.");
        }

        let conn = globalObject.getData("descriptionAPI", "networkInteraction", "connection");           
        if(conn !== null){
            let hex = helpersFunc.getRandomHex();

            //записываем название события для генерации соответствующего ответа
            globalObject.setData("tasks", hex, {
                eventName: "search information tasks",
                userSessionID: sessionId,
            });

            /**
arguments: {
    cptp: false,
    tp: false,
    id: 1221,
    sft: '',
    sfdt: 'complete',
    cpfid: false,
    fid: false,
    cpafid: false,
    afid: false,
    iaf: { fif: false, cafmin: 0, cafmax: 0, safmin: 0, safmax: 0 },
    ifo: { dt: [Object], p: 'any', nf: [Object] }
  }

  o: {
		!!! sriga: <BOOL>, //SearchRequestIsGeneratedAutomatically — был ли запрос на поиск сгенерирован автоматически (TRUE — да, FALSE — нет)
		+cptp: <BOOL>, //ConsiderParameterTaskProcessed — учитывать параметр TaskProcessed
		+tp: <BOOL>, //TaskProcessed — была ли задача отмечена клиентом API как завершенная
		+id: <INT>, //ID - уникальный цифровой идентификатор источника
		+sft: <STRING>, //StatusFilteringTask - статус задачи по фильтрации
		+sfdt: <STRING>, //StatusFileDownloadTask - статус задачи по скачиванию файлов
		+cpfid: <BOOL>, //ConsiderParameterFilesDownloaded — учитывать параметр  FilesIsDownloaded
		+fid: <BOOL>, //FilesIsDownloaded — выполнялась ли выгрузка файлов
		+cpafid: <BOOL>, //ConsiderParameterAllFilesIsDownloaded -  учитывать параметр AllFilesIsDownloaded
		+afid: <BOOL>, //AllFilesIsDownloaded — все ли файлы были выгружены
		+iaf: { //InformationAboutFiltering — поиск информации по результатам фильтрации
			+fif: <BOOL>, //FilesIsFound — были ли найдены в результате фильтрации какие либо файлы
			+cafmin: <INT>, //CountAllFilesMin — минимальное общее количество всех найденных в результате фильтрации файлов
			+cafmax: <INT>, //CountAllFilesMax — максимальное общее количество всех найденных в результате фильтрации файлов
			+safmin: <INT>, //SizeAllFilesMin — минимальный общий размер всех найденных  в результате фильтрации файлов
			+safmax: <INT>, //SizeAllFilesMax — минимальный общий размер всех найденных  в результате фильтрации файлов
		},
		+ifo: { //InstalledFilteringOption — искомые опции фильтрации
			+dt: { //DateTime -  дата и время фильтруемых файлов
				s: <INT>, //Start - начальное дата и время фильтруемых файлов
				e: <INT>, //End - конечное дата и время фильтруемых файлов
			},
			+p: <STRING>, //Protocol — транспортный протокол
			+nf: { //NetworkFilters — сетевые фильтры
				ip: { //IP — фильтры для поиска по ip адресам
					any: <ARRAY>, //Any — вы обе стороны
					src: <ARRAY>, //Src — только как источник
					dst: <ARRAY>, //Dst — только как получатель
				},
				pt: { //Port — фильтры для поиска по сетевым портам
					any: <ARRAY>, //Any — вы обе стороны
					src: <ARRAY>, //Src	 — только как источник
					dst: <ARRAY>, //Dst — только как получатель
				},
				nw: { //Network — фильтры для поиска по подсетям
					any: <ARRAY>, //Any — вы обе стороны
					src: <ARRAY>, //Src — только как источник
					dst: <ARRAY>, //Dst — только как получатель				
				}
			},
		},
	}
 */

            data.sriga = true;

            console.log("--=-==-=-=");
            console.log(data);
            console.log("--=-==-=-=");

            /*
            let tmp = {
                msgType: "command",
                msgSection: "information search control",
                msgInstruction: "search common information",
                taskID: hex,
                options: {
                    sriga: true, //отмечаем что задача выполняется в автоматическом режиме
                    sft: "complete",
                    cptp: true,
                    tp: false,
                    cpfid: true,
                    fid: true,
                    iaf: {
                        fif: true,
                    } 
                },
            };
        
            conn.sendMessage(tmp);
            */
        }    
    });
};