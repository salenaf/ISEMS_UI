"use strict";

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const commons = require("../../libs/helpers/commons");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
const sendCommandsModuleNetworkInteraction = require("../../libs/processing/routeSocketIo/sendCommandsModuleNetworkInteraction");
const informationForPageManagementOrganizationAndSource = require("../../libs/management_settings/informationForPageManagementOrganizationAndSource");

/**
 * Модуль обработчик действий над сущностями (организациями, подразделениями и источниками)
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {   
    const handlers = {
        "add new entitys": addNewEntitys,
        "entity information": getEntityInformation,
        "change source info": changeSourceInfo,
        "delete source info": deleteSourceInfo,
        "change division info": changeDivisionInfo,
        "delete division info": deleteDivisionInfo,
        "change organization info": changeOrganizationInfo,
        "delete organization info": deleteOrganizationInfo,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

//обработчик для добавления новых сущностей
function addNewEntitys(socketIo, data){
    let funcName = " (func 'addNewEntitys')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("management auth", "Пользователь не авторизован.");
            }

            return authData.document.groupSettings.management_organizations_and_sources.element_settings;
        }).then((authData) => {
            //проверяем параметры полученные от пользователя
            let obj = (require("../../libs/processing/routeSocketIo/validationObjectNewEntitys"))(data.arguments);
            obj.authData = authData;

            return obj;
        }).then(({ result: newObjectEntity, errMsg: listErrors, authData: ad }) => {
            //наличие ошибок при валидации данных полученных от пользователя
            if(listErrors.length > 0){
                throw new MyError("management validation", listErrors);
            }

            //проверяем права пользователя на добавление сущностей различных типов
            let { entityList, errMsg } = checkListEntitiesBasedUserPrivileges(newObjectEntity, ad);
            if(errMsg){
                throw errMsg;
            }

            return entityList;
        }).then((entityList) => {
            //добавляем новые сущности в БД
            return (require("../../libs/processing/routeSocketIo/insertNewEntity"))(entityList)
                .then(() => {
                    showNotify({
                        socketIo: socketIo,
                        type: "success",
                        message: "Новые сущности были успешно добавлены в базу данных."
                    }); 
                }).then(() => {
                //подготавливаем список источников
                    let sourceList = entityList.filter((item) => (item.source_settings && item.network_settings));

                    if(sourceList.length > 0){
                    //отправляем новые источники, если они есть, модулю сетевого взаимодействия
                        return sendCommandsModuleNetworkInteraction.sourceManagements(sourceList);
                    }
                });
        }).finally(() => {
            //получаем новый краткий список с информацией по сущностям
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            }).then((shortSourceList) => {             
                socketIo.emit("entity: new short source list", {
                    arguments: shortSourceList,
                }); 
            });
        }).catch((err) => {
            if (err.name === "management auth") {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: err.message.toString()
                });
            } else if (err.name === "management validation") {               
                err.message.forEach((msg) => {
                    showNotify({
                        socketIo: socketIo,
                        type: "danger",
                        message: msg
                    });
                });
            } else if (err.name === "management network interaction") {
                //при отсутствии доступа к модулю сетевого взаимодействия
                showNotify({
                    socketIo: socketIo,
                    type: "warning",
                    message: err.message.toString()
                });            
            } else {
                let msg = "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору.";

                if((err.message.toString()).includes("duplicate key")){
                    msg = "Совпадение ключевых полей, запись в базу данных невозможен.";
                }

                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: msg
                });    
            }

            writeLogFile("error", err.toString()+funcName);
        });    
}

//получить информацию о сущности
function getEntityInformation(socketIo, data){
    let funcName = " (func 'getEntityInformation')";

    switch(data.actionType){
    //информация только по источнику
    case "get info only source":
        checkUserAuthentication(socketIo)
            .then((authData) => {
                //авторизован ли пользователь
                if (!authData.isAuthentication) {
                    throw new MyError("organization and source management", "Пользователь не авторизован.");
                }
            }).then(() => {
                //проверяем параметры полученные от пользователя
                if (!(commons.getRegularExpression("stringAlphaNumEng")).test(data.arguments.sourceID)) {
                    throw new MyError("organization and source management", "Невозможно получить информацию по источнику. Один или более заданных параметров некорректен.");
                }
            }).then(() => {
                //запрос информации к БД
                return new Promise((resolve, reject) => {
                    mongodbQueryProcessor.querySelect(
                        models.modelSourcesParameter, { 
                            query: { id: data.arguments.entityId },
                            select: { _id: 0,  __v: 0, information_about_app: 0, id_division: 0 },
                        }, (err, list) => {
                            if(err) reject(err);
                            else resolve(list);
                        });
                });
            }).then((objInfo) => {
                socketIo.emit("entity: set info only source", {
                    arguments: objInfo,
                });
            }).catch((err) => {
                if (err.name === "organization and source management") {
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

                writeLogFile("error", err.toString()+funcName);
            });

        break;

    //полная информация организация, подразделение и источник
    // поиск по источнику
    case "get info about source":
        checkUserAuthentication(socketIo)
            .then((authData) => {
            //авторизован ли пользователь
                if (!authData.isAuthentication) {
                    throw new MyError("organization and source management", "Пользователь не авторизован.");
                }
            }).then(() => {
            //проверяем параметры полученные от пользователя
                if (!(commons.getRegularExpression("stringAlphaNumEng")).test(data.arguments.sourceID)) {
                    throw new MyError("organization and source management", "Невозможно получить информацию по источнику. Один или более заданных параметров некорректен.");
                }
            }).then(() => {
                //запрос информации к БД
                return new Promise((resolve, reject) => {
                    mongodbQueryProcessor.querySelect(
                        models.modelSourcesParameter, { 
                            query: { id: data.arguments.entityId },
                            select: { _id: 0,  __v: 0 },
                        }, (err, list) => {
                            if(err) reject(err);
                            else resolve(list);
                        });
                }).then((sourceInfo) => {
                    return new Promise((resolve, reject) => {
                        mongodbQueryProcessor.querySelect(
                            models.modelDivisionBranchName, { 
                                query: { id: sourceInfo.id_division },
                                select: { _id: 0,  __v: 0 },
                            }, (err, list) => {
                                if(err) reject(err);
                                else resolve({ source: sourceInfo, division: list });
                            });
                    });
                }).then((objInfo) => {
                    return new Promise((resolve, reject) => {
                        mongodbQueryProcessor.querySelect(
                            models.modelOrganizationName, { 
                                query: { id: objInfo.division.id_organization },
                                select: { _id: 0,  __v: 0 },
                            }, (err, list) => {
                                if(err) reject(err);
                        
                                objInfo.organization = list;
                                resolve(objInfo);
                            });
                    });
                });        
            }).then((objInfo) => {
                socketIo.emit("entity: set info about source", {
                    arguments: objInfo,
                });
            }).catch((err) => {
                if (err.name === "organization and source management") {
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

                writeLogFile("error", err.toString()+funcName);
            });

        break;

    //информация по организации и подразделению
    // поиск по любому ID: организации, подразделению или источнику
    case "get info about organization or division":
        checkUserAuthentication(socketIo)
            .then((authData) => {
                //авторизован ли пользователь
                if (!authData.isAuthentication) {
                    throw new MyError("organization and source management", "Пользователь не авторизован.");
                }
            }).then(() => {
                //проверяем параметры полученные от пользователя
                if (!(commons.getRegularExpression("stringAlphaNumEng")).test(data.arguments.value)) {
                    throw new MyError("organization and source management", "Невозможно получить информацию. Один или более заданных параметров некорректен.");
                }
            }).then(() => {
                switch(data.arguments.type){
                case "organization":
                    return getInformationAboutOrganizationID(data.arguments.value)
                        .then((result) => {
                            socketIo.emit("entity: set info about organization and division", {
                                arguments: result
                            });
                        }).catch((err) => {
                            throw err;
                        });

                case "division":
                    return new Promise((resolve, reject) => {
                        mongodbQueryProcessor.querySelect(
                            models.modelDivisionBranchName, { 
                                query: { id: data.arguments.value },
                                select: { id_organization: 1 },
                            }, (err, organizationInfo) => {
                                if(err) reject(err);
                                else resolve(organizationInfo.id_organization);
                            });

                    }).then((organizationId) => {
                        return getInformationAboutOrganizationID(organizationId)
                            .then((result) => {
                                socketIo.emit("entity: set info about organization and division", {
                                    arguments: result
                                });
                            }).catch((err) => {
                                throw err;
                            });
                    }).catch((err) => {
                        throw err;
                    });

                case "source":
                    return new Promise((resolve, reject) => {
                        mongodbQueryProcessor.querySelect(
                            models.modelDivisionBranchName, { 
                                query: { source_list: data.arguments.value },
                                select: { id_organization: 1 },
                            }, (err, organizationInfo) => {
                                if(err) reject(err);
                                else resolve(organizationInfo.id_organization);
                            });

                    }).then((organizationId) => {
                        return getInformationAboutOrganizationID(organizationId)
                            .then((result) => {
                                socketIo.emit("entity: set info about organization and division", {
                                    arguments: result
                                });
                            }).catch((err) => {
                                throw err;
                            });
                    }).catch((err) => {
                        throw err;
                    });
                }
            }).catch((err) => {
                if (err.name === "organization and source management") {
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

                writeLogFile("error", err.toString()+funcName);
            });

        break;
    }
}

function getInformationAboutOrganizationID(organizationID){
    return new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(
            models.modelOrganizationName, { 
                query: { id: organizationID },
                select: { _id: 0, __v: 0 },
            }, (err, result) => {
                if(err) reject(err);
                else resolve(result);
            });
    }).then((orgInfo) => {
        let newObj = {
            id: orgInfo.id,
            organizationName: orgInfo.name,
            organizationNameIsValid: true,
            organizationNameIsInvalid: false,
            dateRegister: orgInfo.date_register,
            dateChange: orgInfo.date_change,
            fieldActivity: orgInfo.field_activity,
            legalAddress: orgInfo.legal_address,
            legalAddressIsValid: true,
            legalAddressIsInvalid: false,
            listDivision: [],
        };

        if(orgInfo.division_or_branch_list_id.length === 0){
            return newObj;
        }

        return getInformationAboutDivision(orgInfo.division_or_branch_list_id)
            .then((listInfo) => {
                newObj.listDivision = listInfo;

                return newObj;
            });
    });
}

function getInformationAboutDivision(listDivision){
    return new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(
            models.modelDivisionBranchName, { 
                isMany: true,
                query: { id: listDivision },
                select: { _id: 0,  __v: 0 },
            }, (err, result) => {
                if(err) reject(err);
                else resolve(result);
            });
    }).then((listDivisionInfo) => {
        return Promise.all(listDivisionInfo.map((divisionInfo) => {
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.querySelect(
                    models.modelSourcesParameter, { 
                        isMany: true,
                        query: { id: divisionInfo.source_list },
                        select: { _id: 0, source_id: 1,  short_name: 1 },
                    }, (err, sourceList) => {
                        if(err) reject(err);
                        else resolve({
                            id: divisionInfo.id,
                            divisionName: divisionInfo.name,
                            divisionNameIsValid: true,
                            divisionNameIsInvalid: false,
                            dateRegister: divisionInfo.date_register,
                            dateChange: divisionInfo.date_change,
                            physicalAddress: divisionInfo.physical_address,
                            physicalAddressIsValid: true,
                            physicalAddressIsInvalid: false,
                            description: divisionInfo.description,
                            listSource: sourceList,
                        });
                    });
            });
        }));
    });
}

//изменить информацию об источнике
function changeSourceInfo(socketIo, data){
    let checkSourceValue = (obj, callback) => {
        let commonPattern = {
            "id": {
                "namePattern": "stringAlphaNumEng",
                "messageError": "принят некорректный идентификатор источника",
            },
            "source_id": {
                "namePattern": "hostID",
                "messageError": "идентификатор источника не является числом",
            },
            "short_name": {
                "namePattern": "shortNameHost",
                "messageError": "обнаружен недопустимый символ в кратком названии организации",
            },
        };
    
        let networkPattern = {
            "ipaddress": {
                "namePattern": "ipaddress",
                "messageError": "принят некорректный ip адрес",
            },
            "port": {
                "namePattern": "port",
                "messageError": "принят некорректный порт",
            },
            "token_id": {
                "namePattern": "stringAlphaNumEng",
                "messageError": "принят некорректный идентификационный токен",
            },
        };
    
        //проверяем наличие всех элементов
        for(let elemName in commonPattern){
            if(typeof obj[elemName] === "undefined"){
                return callback(new Error("отсутствует некоторая информацией об источнике"));
            }
    
            if(!helpersFunc.checkInputValidation({
                name: commonPattern[elemName].namePattern,
                value: obj[elemName],
            })){
                return callback(commonPattern[elemName].messageError);
            }
        }
    
        //проверяем сетевые настройки источника
        for(let elemName in networkPattern){
            if(obj.network_settings[elemName] === "undefined"){           
                return new Error("отсутствует некоторая информация, необходимая для осуществления сетевого соединения с источником");
            }
    
            if(!helpersFunc.checkInputValidation({
                name: networkPattern[elemName].namePattern,
                value: obj.network_settings[elemName]
            })){
                return callback(networkPattern[elemName].messageError);
            }
        }
    
        // проверяем параметры источника
        let tacs = obj.source_settings.type_architecture_client_server;
        if((typeof tacs === "undefined") || (tacs !== "server")){
            obj.source_settings.type_architecture_client_server = "client";
        }
    
        let tt = obj.source_settings.transmission_telemetry;
        if((typeof tt === "undefined") || (!tt)){
            obj.source_settings.transmission_telemetry = false;
        } else {
            obj.source_settings.transmission_telemetry = true;
        }
    
        let mnsfp = obj.source_settings.maximum_number_simultaneous_filtering_processes;
        if((typeof mnsfp === "undefined") || (+mnsfp <= 0 || +mnsfp > 10)){
            obj.source_settings.maximum_number_simultaneous_filtering_processes = 5;    
        }
    
        let tclp = obj.source_settings.type_channel_layer_protocol;
        if((typeof tclp === "undefined") || (tclp != "pppoe")){
            obj.source_settings.type_channel_layer_protocol = "ip";    
        }
    
        let ldwfnt = obj.source_settings.list_directories_with_file_network_traffic;
        if(typeof ldwfnt === "undefined"){
            return callback(new Error("не заданы директории в которых выполняется фильтрация сет. трафика"));
        }
        let newListFolder = ldwfnt.filter((folder) => helpersFunc.checkInputValidation({
            name: "folderStorage",
            value: folder,
        }));
        obj.source_settings.list_directories_with_file_network_traffic = newListFolder;
    
        //проверяем поле description
        if(!helpersFunc.checkInputValidation({ 
            name: "inputDescription", 
            value: obj.description,
        })){
            obj.description = "";
        }
        
        callback(null, obj);
    };

    let funcName = " (func 'changeSourceInfo')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            //может ли пользователь изменять информацию об источнике
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_sources.element_settings.edit.status) {
                throw new MyError("organization and source management", "Невозможно изменить информацию об источнике. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {          
            //проверяем параметры полученные от пользователя
            return new Promise((resolve, reject) => {
                checkSourceValue(data, (err, validData) => {
                    if(err){
                        reject(new MyError("organization and source management", err.toString()));
                    } else {
                        resolve(validData);
                    }
                });
            });
        }).then((validData) => {
            //обновляем информацию в БД
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelSourcesParameter, {
                    query: { id: validData.id },
                    update: {
                        source_id: validData.source_id,
                        date_change: +(new Date),
                        short_name: validData.short_name,
                        description: validData.description,
                        network_settings: validData.network_settings,
                        source_settings: validData.source_settings,
                    },
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }).then(() => {
            //получаем новый краткий список с информацией по сущностям
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });            

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Информация по источнику ${data.source_id} была успешно изменена.`
            });       

        }).catch((err) => {
            if (err.name === "organization and source management") {
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

            writeLogFile("error", err.toString()+funcName);        
        });
}

//удалить всю информацию по источнику
function deleteSourceInfo(socketIo, data){
    let funcName = " (func 'deleteSourceInfo')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            //может ли пользователь удалять информацию об источнике
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_sources.element_settings.delete.status) {
                throw new MyError("organization and source management", "Невозможно удалить выбранные источники. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            //удаляем выбранные источники           
            return Promise.all(data.arguments.listSource.map((item) => {
                return new Promise((resolve, reject) => {
                    mongodbQueryProcessor.queryDelete(models.modelSourcesParameter, {
                        query: { "id": item.sourceId },
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                }).then(() => {
                    return new Promise((resolve, reject) => {
                        mongodbQueryProcessor.queryUpdate(models.modelDivisionBranchName, {
                            query: { id: item.divisionId },
                            update: { "$pull": { "source_list": item.sourceId }}
                        }, (err) => {
                            if(err) reject(err);
                            else resolve();
                        });
                    });
                });
            }));
        }).then(() => {
            //получаем новый краткий список с информацией по источникам
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            //отправляем новый список в интерфейс
            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });            

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Источники с номерами ${data.arguments.listSource.map((item) => item.source).join(",")} были успешно удалены. `
            });      
        }).catch((err) => {
            if (err.name === "organization and source management") {
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

            writeLogFile("error", err.toString()+funcName);        
        });
}

//изменить информацию о подразделении
function changeDivisionInfo(socketIo, data){
    let funcName = " (func 'changeDivisionInfo')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            //может ли пользователь изменять информацию об источнике
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_division.element_settings.edit.status) {
                throw new MyError("organization and source management", "Невозможно изменить информацию о подразделении. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            let commonPattern = {
                "divisionName": {
                    "namePattern": "fullNameHost",
                    "messageError": "название подразделения или филиала содержит недопустимые значения",
                },
                "physicalAddress": {
                    "namePattern": "stringRuNumCharacter",
                    "messageError": "физический адрес подразделения содержит недопустимые значения",
                },
                "description": {
                    "namePattern": "inputDescription",
                    "messageError": "обнаружен недопустимый символ в дополнительном описании подразделения",
                },
            };

            let errMsgCommon = "Невозможно изменить информацию о подразделении. Получены некорректные параметры.";

            if(typeof data.arguments === "undefined" || data.arguments.length === 0){
                throw new MyError("organization and source management", errMsgCommon);
            }

            //проверяем параметры полученные от пользователя
            return new Promise((resolve, reject) => {
                if (!(commons.getRegularExpression("stringAlphaNumEng")).test(data.entityId)) {
                    reject(new MyError("organization and source management", errMsgCommon));
                }
                
                for(let elem in commonPattern){
                    if(typeof data.arguments[elem] === "undefined"){
                        throw new MyError("organization and source management", errMsgCommon);
                    }

                    if(!helpersFunc.checkInputValidation({
                        name: commonPattern[elem].namePattern, 
                        value: data.arguments[elem],
                    })){
                        reject(new MyError("organization and source management", commonPattern[elem].messageError));
                    }
                }

                resolve();
            });
        }).then(() => {
            //обновляем информацию в БД
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelDivisionBranchName, {
                    query: { id: data.entityId },
                    update: {
                        name: data.arguments.divisionName,
                        physical_address: data.arguments.physicalAddress,
                        description: data.arguments.description,
                        date_change: +(new Date),
                    },
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }).then(() => {
            //получаем новый краткий список с информацией по источникам
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });         

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Информация о подразделении '${data.arguments.divisionName}'' была успешно изменена.`
            });  
        }).catch((err) => {
            if (err.name === "organization and source management") {
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

            writeLogFile("error", err.toString()+funcName);        
        });
}

//удалить всю информацию о подразделении
function deleteDivisionInfo(socketIo, data){
    let funcName = " (func 'deleteDivisionInfo')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            //может ли пользователь удалять информацию о подразделении
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_division.element_settings.delete.status) {
                throw new MyError("organization and source management", "Невозможно удалить подразделение. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {           
            //удаляем выбранное подразделение
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryDelete(models.modelDivisionBranchName, {
                    query: { 
                        "id": data.arguments.divisionId, 
                        "source_list": { "$size": 0 },
                    },
                }, (err, deleteObj) => {
                    if (err) reject(err);
                    else resolve(deleteObj);
                });
            });
        }).then((deleteObj) => {
            if(!deleteObj){
                return;
            }

            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelOrganizationName, {
                    query: { id: data.arguments.organizationId },
                    update: { "$pull": { "division_or_branch_list_id": data.arguments.divisionId }}
                }, (err) => {
                    if(err) reject(err);
                    else resolve();
                });
            });
        }).then(() => {
            //получаем новый краткий список с информацией по источникам
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            //отправляем новый список в интерфейс
            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });            

            socketIo.emit("entity: delete division", {
                arguments: {
                    divisionId: data.arguments.divisionId,
                    organizationId: data.arguments.organizationId,
                }
            });

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Выбранное подразделение было успешно удалено."
            });      
        }).catch((err) => {
            if (err.name === "organization and source management") {
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

            writeLogFile("error", err.toString()+funcName);        
        });
}

//изменить информацию об организации
function changeOrganizationInfo(socketIo, data){
    let funcName = " (func 'changeOrganizationInfo')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            //может ли пользователь изменять информацию об источнике
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_division.element_settings.edit.status) {
                throw new MyError("organization and source management", "Невозможно изменить информацию об организации. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            let listFieldActivity = globalObject.getData("commonSettings", "listFieldActivity");
            let errMsgCommon = "Невозможно изменить информацию об организации. Получены некорректные параметры.";
            let commonPattern = {
                "organizationName": {
                    "namePattern": "fullNameHost",
                    "messageError": "название организации содержит недопустимые значения",
                },
                "legalAddress": {
                    "namePattern": "stringRuNumCharacter",
                    "messageError": "юридический адрес организации содержит недопустимые значения",
                },
            };

            if(typeof data.arguments === "undefined" || data.arguments.length === 0){
                throw new MyError("organization and source management", errMsgCommon);
            }

            //проверяем сферу деятельности
            if(!listFieldActivity.some((i) => i === data.arguments.fieldActivity)){
                data.arguments.fieldActivity = "иная деятельность";
            }

            //проверяем параметры полученные от пользователя
            return new Promise((resolve, reject) => {
                if (!(commons.getRegularExpression("stringAlphaNumEng")).test(data.entityId)) {
                    reject(new MyError("organization and source management", errMsgCommon));
                }
                
                for(let elem in commonPattern){
                    if(!helpersFunc.checkInputValidation({ 
                        name: commonPattern[elem].namePattern, 
                        value: data.arguments[elem],
                    })){
                        reject(new MyError("organization and source management", commonPattern[elem].messageError));
                    }
                }

                resolve();
            });
        }).then(() => {
            //обновляем информацию в БД
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryUpdate(models.modelOrganizationName, {
                    query: { id: data.entityId },
                    update: {
                        name: data.arguments.organizationName,
                        legal_address: data.arguments.legalAddress,
                        field_activity: data.arguments.fieldActivity,
                        date_change: +(new Date),
                    },
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }).then(() => {
            //получаем новый краткий список с информацией по источникам
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });          

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Информация об организации '${data.arguments.organizationName}' была успешно изменена.`
            });
        }).catch((err) => {
            if (err.name === "organization and source management") {
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

            writeLogFile("error", err.toString()+funcName);        
        });
}

//удалить всю информацию об организации
function deleteOrganizationInfo(socketIo, data){
    let funcName = " (func 'deleteOrganizationInfo')";

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            //может ли пользователь удалять информацию об организации
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_organizations.element_settings.delete.status) {
                throw new MyError("organization and source management", "Невозможно удалить организацию. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {          
            //удаляем выбранное подразделение
            return new Promise((resolve, reject) => {
                mongodbQueryProcessor.queryDelete(models.modelOrganizationName, {
                    query: { 
                        "id": data.arguments.organizationId, 
                        "division_or_branch_list_id": { "$size": 0 },
                    },
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        }).then(() => {
            //получаем новый краткий список с информацией по источникам
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });          

            socketIo.emit("entity: delete organization", {
                arguments: {
                    organizationId: data.arguments.organizationId
                },
            });            

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Выбранная организация была успешно удалена."
            });      
        }).catch((err) => {
            if (err.name === "organization and source management") {
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

            writeLogFile("error", err.toString()+funcName);        
        });
}

/**
 * Функция проверяет права пользователя на добавление новых сущьностей
 * возвращает список сущьностей которые текущий пользователь может добавлять  
 * 
 * @param {*} listEntity 
 * @param {*} userPermission 
 */
function checkListEntitiesBasedUserPrivileges(listEntity, userPermission){
    let addOrg = userPermission.management_organizations.element_settings.create.status;
    let addDivi = userPermission.management_division.element_settings.create.status;
    let addSour = userPermission.management_sources.element_settings.create.status;

    //действие разрешено для всех сущностей
    if(addOrg && addDivi && addSour){
        return { entityList: listEntity, errMsg: null };
    }

    //действие запрещено для всех сущностей
    if(!addOrg && !addDivi && !addSour){
        return { entityList: [], errMsg: new Error("пользователю полностью запрещено добавлять новые сущности") };
    }

    let newEntityList = listEntity.filter((item) => {
        let orgId = (typeof item.id_organization === "undefined");
        let divId = (typeof item.id_division === "undefined");

        if(!orgId && divId){
        //для организации        
            if(addOrg){
                return true;
            }
        } else if(!orgId && !divId){
        //для подразделения
            if(addDivi){
                return true;
            }
        } else {
        //для источника            
            if(addSour){
                return true;
            }
        }

        return false;
    });

    return { entityList: newEntityList, errMsg: null};
}