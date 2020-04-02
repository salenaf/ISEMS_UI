"use strict";

const async = require("async");
const debug = require("debug")("handlerOAS");

const models = require("../../controllers/models");
const MyError = require("../../libs/helpers/myError");
const commons = require("../../libs/helpers/commons");
const showNotify = require("../../libs/showNotify");
const helpersFunc = require("../../libs/helpers/helpersFunc");
const writeLogFile = require("../../libs/writeLogFile");
const mongodbQueryProcessor = require("../../middleware/mongodbQueryProcessor");
const checkUserAuthentication = require("../../libs/check/checkUserAuthentication");
//const validationObjectNewEntitys = require("../../libs/processing/routeSocketIo/validationObjectNewEntitys");
const informationForPageManagementOrganizationAndSource = require("../../libs/management_settings/informationForPageManagementOrganizationAndSource");

/**
 * Модуль обработчик действий над сущностями (организациями, подразделениями и источниками)
 *
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {
    debug("func 'addHandlers', START...");
    
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
//    debug("func 'addNewEntitys', START...");
//    debug(data);

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
            return (require("../../libs/processing/routeSocketIo/insertNewEntity"))(entityList);
        }).then(() => {
            showNotify({
                socketIo: socketIo,
                type: "success",
                message: "Новые сущности были успешно добавлены."
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
                    message: err.message
                });
            } else if (err.name === "management validation") {               
                err.message.forEach((msg) => {
                    showNotify({
                        socketIo: socketIo,
                        type: "danger",
                        message: msg
                    });
                });
            } else {
                showNotify({
                    socketIo: socketIo,
                    type: "danger",
                    message: "Внутренняя ошибка приложения. Пожалуйста обратитесь к администратору."
                });    
            }

            writeLogFile("error", err.toString());
        });
     
}

//получить информацию о сущности
function getEntityInformation(socketIo, data){
    //debug("func 'getEntityInformation', START...");
    //debug(data);

    switch(data.actionType){
    //информация только по источнику
    case "get info only source":
        //debug("INFORMATION ONLY SOURCE");

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
                debug(`sending information to DB about id: ${data.arguments.entityId}`);

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
                debug(objInfo);

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

                writeLogFile("error", err.toString());
            });

        break;

    //полная информация организация, подразделение и источник
    // поиск по источнику
    case "get info about source":

        //debug("INFORMATION ABOUT SOURCE");

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
                //debug(`sending information to DB about id: ${data.arguments.entityId}`);

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
                //debug(objInfo);

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

                writeLogFile("error", err.toString());
            });

        break;

    //информация по организации и подразделению
    // поиск по любому ID: организации, подразделению или источнику
    case "get info about organization or division":

        debug("INFORMATION ABOUT ORGANIZATION OR DIVISION");
        debug(data);

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
                switch(data.type){
                case "organization":
                    socketIo.emit("entity: set info about organization and division", {
                        arguments: getInformationAboutOrganizationID(data.arguments.value)
                    });
                    /**
 * Сделать обработчики для получения
 * информации об организации и подразделениях
 * по ID организации, подразделении или источнику
 * 
 */
                    break;

                case "division":

                    break;

                case "source":


                }
            }).catch((err) => {
                debug("ERROR:");
                debug(err);
            });

        break;
    }
}

function getInformationAboutOrganizationID(organizationID){
    debug("func 'getInformationAboutOrganizationID'");
    debug(organizationID);

    return new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(
            models.modelOrganizationName, { 
                query: { id: organizationID },
                select: { _id: 0,  __v: 0 },
            }, (err, result) => {
                if(err) reject(err);
                else resolve(result);
            });
    }).then((orgInfo) => {
        debug("Info about organization");
        debug(orgInfo.division_or_branch_list_id);

        if(orgInfo.division_or_branch_list_id.length === 0){
            return orgInfo;
        }

        let promises = orgInfo.division_or_branch_list_id.map((id) => {
            return getInformationAboutDivisionID(id);
        });

        Promise.all(promises)
            .then(() => {
                //здесь собрать новый orgInfo добавив в
                // division_or_branch_list_id объекты подразделений
            }).catch((err) => {
                throw err;
            });
    });
}

function getInformationAboutDivisionID(divisionID){
    return new Promise((resolve, reject) => {
        mongodbQueryProcessor.querySelect(
            models.modelDivisionBranchName, { 
                query: { id: divisionID },
                select: { _id: 0,  __v: 0 },
            }, (err, result) => {
                if(err) reject(err);
                else resolve(result);
            });
    });
}

//изменить информацию об источнике
function changeSourceInfo(socketIo, data){
    debug("func 'changeSourceInfo', START...");
    debug(data);

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

    checkUserAuthentication(socketIo)
        .then((authData) => {
            //debug("авторизован ли пользователь");

            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            //debug("может ли пользователь изменять информацию об источнике");

            //может ли пользователь изменять информацию об источнике
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_sources.element_settings.edit.status) {
                throw new MyError("organization and source management", "Невозможно изменить информацию об источнике. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            
            //debug("проверяем параметры полученные от пользователя");
            
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
            
            //debug("обновляем информацию в БД");
            //debug(validData);

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

            //debug("получаем новый краткий список с информацией по источникам");

            //получаем новый краткий список с информацией по сущностям
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            //отправляем новый список в интерфейс
            //debug("отправляем новый список в интерфейс");
            //debug("------ RESIVED NEW shortSourceList ------");
            //debug(shortSourceList);

            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });            

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Информация по источнику ${data.source_id} была успешно изменена.`
            });       

        }).catch((err) => {
            //debug("ERROR-------------------------");
            //debug(err);

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

            writeLogFile("error", err.toString());        
        });
}

//удалить всю информацию по источнику
function deleteSourceInfo(socketIo, data){
    debug("func 'deleteSourceInfo', START...");
    debug(data);

    checkUserAuthentication(socketIo)
        .then((authData) => {
            debug("авторизован ли пользователь");

            //авторизован ли пользователь
            if (!authData.isAuthentication) {
                throw new MyError("organization and source management", "Пользователь не авторизован.");
            }

            debug("может ли пользователь удалять информацию об источнике");

            //может ли пользователь изменять информацию об источнике
            if (!authData.document.groupSettings.management_organizations_and_sources.element_settings.management_sources.element_settings.delete.status) {
                throw new MyError("organization and source management", "Невозможно удалить выбранные источники. Недостаточно прав на выполнение данного действия.");
            }
        }).then(() => {
            //удаляем выбранные источники
            debug("удаляем выбранные источники");
            
            return Promise.all(data.arguments.listSource.map((item) => {
                
                debug(`delete source id ${item}`);

                return new Promise((resolve, reject) => {
                    mongodbQueryProcessor.queryDelete(models.modelSourcesParameter, {
                        query: { "source_id": item },
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            }));
        }).then(() => {

            debug("получаем новый краткий список с информацией по источникам");

            //получаем новый краткий список с информацией по источникам
            return new Promise((resolve, reject) => {
                informationForPageManagementOrganizationAndSource((err, result) => {
                    if (err) reject(err);
                    else resolve(result);
                });
            });
        }).then((shortSourceList) => {           
            //отправляем новый список в интерфейс
            debug("отправляем новый список в интерфейс");
            debug("------ RESIVED NEW shortSourceList ------");
            //debug(shortSourceList);

            socketIo.emit("entity: new short source list", {
                arguments: shortSourceList,
            });            

            showNotify({
                socketIo: socketIo,
                type: "success",
                message: `Источники с номерами ${data.arguments.listSource.join(",")} были успешно удалены. `
            });      
        }).catch((err) => {
            debug("ERROR-------------------------");
            debug(err);

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

            writeLogFile("error", err.toString());        
        });
}

//изменить информацию о подразделении
function changeDivisionInfo(socketIo, data){
    debug("func 'changeDivisionInfo', START...");
    debug(data);
}

//удалить всю информацию о подразделении
function deleteDivisionInfo(socketIo, data){
    debug("func 'deleteDivisionInfo', START...");
    debug(data);
}

//изменить информацию об организации
function changeOrganizationInfo(socketIo, data){
    debug("func 'changeOrganizationInfo', START...");
    debug(data);
}

//удалить всю информацию об организации
function deleteOrganizationInfo(socketIo, data){
    debug("func 'deleteOrganizationInfo', START...");
    debug(data);
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