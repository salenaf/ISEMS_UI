"use strict";

const MyError = require("../../helpers/myError");
const helpersFunc = require("../../helpers/helpersFunc");
const globalObject = require("../../../configure/globalObject");

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками
  * Выполняет добавление новых источников в базу данных модуля 
  * 
  * @param {*} - sourceList
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

                //добавляем новую задачу
                globalObject.setData("tasks", "networkInteractionTaskList", hex, {
                    createDate: +(new Date),
                    typeTask: "command",
                    sectionTask: "source control",
                    instructionTask: "add source list",
                    source: sources,
                });
            }    

            resolve();
        });
    });
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками
  * Выполняет обновление информации об источнике в базе данных модуля 
  * 
  * @param {*} - sourceList
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

                //добавляем новую задачу
                globalObject.setData("tasks", "networkInteractionTaskList", hex, {
                    createDate: +(new Date),
                    typeTask: "command",
                    sectionTask: "source control",
                    instructionTask: "update source list",
                    source: sources,
                });
            }    

            resolve();
        });
    });
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками
  * Выполняет удаление источников из базы данных модуля 
  * 
  * @param {*} - sourceList
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

            console.log(list);

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

                //добавляем новую задачу
                globalObject.setData("tasks", "networkInteractionTaskList", hex, {
                    createDate: +(new Date),
                    typeTask: "command",
                    sectionTask: "source control",
                    instructionTask: "add source list",
                    source: sources,
                });
            }    

            resolve();
        });
    });    
};

/**
  * Обработчик для модуля сетевого взаимодействия осуществляющий
  * управление удаленными источниками
  * Выполняет удаление источников из базы данных модуля 
  * 
  * @param {*} - sourceList
  */
module.exports.sourceManagementsReconnect = function(sourceList){
    console.log("func 'sourceManagementsReconnect'");

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

            console.log(`sourceNotFound: ${sourceNotFound.length}, sourceNotConnection: ${sourceNotConnection.length}`);
            console.log(sources);

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


                /**
                * Переподключение вроде работает,
                *   но неплохо бы еще потестировать
                * 
                * !!! При переходе с любой страницы на страницу управления
                * модулем сетевого взаимодействия почему то страница считает
                * что модуль не подключен!!!
                * 
                * Дальше доделать виджеты
                * 
                */

                //добавляем новую задачу
                /*globalObject.setData("tasks", "networkInteractionTaskList", hex, {
                    createDate: +(new Date),
                    typeTask: "command",
                    sectionTask: "source control",
                    instructionTask: "add source list",
                    source: sources,
                });*/
            }

            resolve();
        });
    });    
};