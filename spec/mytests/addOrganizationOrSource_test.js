"use strict";

const async = require("async");

const config = require("../../configure");

const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const connectMongoDB = require("../../controllers/connectMongoDB");

beforeAll(async() => {
    await connectMongoDB()
        .then(description => {
            return new Promise((resolve, reject) => {
                process.nextTick(() => {
                    globalObject.setData("descriptionDB", "MongoDB", {
                        "connection": description,
                        "connectionTimestamp": +new Date(),
                        "userName": config.get("mongoDB:user")
                    });

                    let connectDB = globalObject.getData("descriptionDB", "MongoDB", "connection");

                    if (connectDB === null) reject(new Error("the database connection is not established"));
                    else resolve(null);
                });
            });
        }).then(() => {

            console.log("create DB connection");

            return new Promise((resolve, reject) => {
                require("../../controllers/createSchemasMongoDB")(err => {
                    if (err) reject(err);
                    else resolve(null);
                });
            });
        }).catch(err => {
            console.log(err);
        });
});

(() => {           
    globalObject.setData("commonSettings", "listFieldActivity", config.get("appSettings:listFieldActivity"));
})();

let orgName = "Новая организация";
let hexSumOrg = (require("../../libs/helpers/createUniqID")).getMD5(`organization_name_${orgName}`);

let divisionName = "Новое подразделение";
let hexSumDiv = (require("../../libs/helpers/createUniqID")).getMD5(`division_name_${divisionName}`);

let sourceID = 1001;
let hexSumSource = (require("../../libs/helpers/createUniqID")).getMD5(`source_name_${sourceID}`);

let hexSumSourceTwo = (require("../../libs/helpers/createUniqID")).getMD5("source_name_1010");

/*afterAll(async() => {
    //удаляем организацию
    await (require("../../middleware/mongodbQueryProcessor")).queryDelete(require("../../controllers/models").modelOrganizationName, {
        query: { "id": hexSumOrg },
    }, (err) => {
        console.log(err);
    });

    //удаляем подразделение
    await (require("../../middleware/mongodbQueryProcessor")).queryDelete(require("../../controllers/models").modelDivisionBranchName, {
        query: { "id": hexSumDiv },
    }, (err) => {
        console.log(err);
    });

    //удаляем два источника
    await (require("../../middleware/mongodbQueryProcessor")).queryDelete(require("../../controllers/models").modelSourcesParameter, {
        query: { "id": hexSumSource },
    }, (err) => {
        console.log(err);
    });
    await (require("../../middleware/mongodbQueryProcessor")).queryDelete(require("../../controllers/models").modelSourcesParameter, {
        query: { "id": hexSumSourceTwo },
    }, (err) => {
        console.log(err);
    });
});*/

function getValidObjectOrganizationOrSource(listOrgOrSource, listFieldActivity) {
    console.log("func 'getValidObjectOrganizationOrSource', START...");

    let checkOrganization = (listOrgOrSource, listFieldActivity) => {
        let pattern = {
            "id_organization": {
                "namePattern": "stringAlphaNumEng",
                "messageError": "принят некорректный идентификатор организации",
            },
            "name": {
                "namePattern": "fullNameHost",
                "messageError": "название организации содержит недопустимые значения",
            },
            "legal_address": {
                "namePattern": "stringRuNumCharacter",
                "messageError": "юридический адрес организации содержит недопустимые значения",
            },
        };

        //проверяем наличие всех элементов
        for(let elemName in pattern){
            if(listOrgOrSource[elemName] === "undefined"){
                errMsg.push("в объекте с информацией об организации отсутствуют некоторые поля");

                return;
            }

            if(!helpersFunc.checkInputValidation({
                name: pattern[elemName].namePattern,
                value: listOrgOrSource[elemName],
            })){
                errMsg.push(pattern[elemName].messageError);

                return;
            }
        }

        //проверяем сферу деятельности
        if(!listFieldActivity.some((i) => i === listOrgOrSource.field_activity)){
            listOrgOrSource.field_activity = "иная деятельность";
        }

        newList.push({
            "id_organization":listOrgOrSource.id_organization,
            "name": listOrgOrSource.name,
            "legal_address": listOrgOrSource.legal_address,
            "field_activity": listOrgOrSource.field_activity,
        });

        if(listOrgOrSource.division_or_branch_list_id.length > 0){
            processListOrgOrSource(listOrgOrSource.division_or_branch_list_id);
        }
    };

    let checkDivision = (listOrgOrSource) => {
        let pattern = {
            "id_organization": {
                "namePattern": "stringAlphaNumEng",
                "messageError": "принят некорректный идентификатор организации",
            },
            "id_division": {
                "namePattern": "stringAlphaNumEng",
                "messageError": "принят некорректный идентификатор подразделения или филиала",
            },
            "name": {
                "namePattern": "fullNameHost",
                "messageError": "название подразделения или филиала содержит недопустимые значения",
            },
            "physical_address": {
                "namePattern": "stringRuNumCharacter",
                "messageError": "физический адрес подразделения содержит недопустимые значения",
            },
        };

        //проверяем наличие всех элементов
        for(let elemName in pattern){
            if(listOrgOrSource[elemName] === "undefined"){
                errMsg.push("в объекте с информацией о подразделении отсутствуют некоторые поля");
                
                return;
            }

            if(!helpersFunc.checkInputValidation({
                name: pattern[elemName].namePattern,
                value: listOrgOrSource[elemName],
            })){
                errMsg.push(pattern[elemName].messageError);

                return;
            }
        }

        //проверяем поле description
        let description = ""; 
        if(helpersFunc.checkInputValidation({ 
            name: "inputDescription", 
            value: listOrgOrSource.description,
        })){
            description = listOrgOrSource.description;
        }

        newList.push({
            "id_organization": listOrgOrSource.id_organization,
            "id_division": listOrgOrSource.id_division,
            "name": listOrgOrSource.name,
            "physical_address": listOrgOrSource.physical_address,
            "description": description,
        });

        if(listOrgOrSource.source_list.length > 0){
            processListOrgOrSource(listOrgOrSource.source_list);
        }
    };

    let checkSource = (listOrgOrSource) => {
        let commonPattern = {
            "id_division": {
                "namePattern": "stringAlphaNumEng",
                "messageError": "принят некорректный идентификатор подразделения или филиала",
            },
            "id_source": {
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
            if(typeof listOrgOrSource[elemName] === "undefined"){
                errMsg.push("отсутствует некоторая информацией об источнике");

                return;
            }
       
            if(!helpersFunc.checkInputValidation({
                name: commonPattern[elemName].namePattern,
                value: listOrgOrSource[elemName],
            })){
                errMsg.push(commonPattern[elemName].messageError);

                return;
            }
        }

        //проверяем сетевые настройки источника
        for(let elemName in networkPattern){
            if(listOrgOrSource.network_settings[elemName] === "undefined"){
                errMsg.push("отсутствует некоторая информация, необходимая для осуществления сетевого соединения с источником");
                
                return;
            }

            if(!helpersFunc.checkInputValidation({
                name: networkPattern[elemName].namePattern,
                value: listOrgOrSource.network_settings[elemName]
            })){
                errMsg.push(networkPattern[elemName].messageError);

                return;
            }
        }

        // проверяем параметры источника
        let tacs = listOrgOrSource.source_settings.type_architecture_client_server;
        if((typeof tacs === "undefined") || (tacs !== "server")){
            listOrgOrSource.source_settings.type_architecture_client_server = "client";
        }

        let tt = listOrgOrSource.source_settings.transmission_telemetry;
        if((typeof tt === "undefined") || (tt !== "on")){
            listOrgOrSource.source_settings.transmission_telemetry = "off";
        }

        let mnsfp = listOrgOrSource.source_settings.maximum_number_simultaneous_filtering_processes;
        if((typeof mnsfp === "undefined") || (+mnsfp <= 0 || +mnsfp > 10)){
            listOrgOrSource.source_settings.maximum_number_simultaneous_filtering_processes = 5;    
        }

        let tclp = listOrgOrSource.source_settings.type_channel_layer_protocol;
        if((typeof tclp === "undefined") || (tclp != "pppoe")){
            listOrgOrSource.source_settings.type_channel_layer_protocol = "ip";    
        }

        let ldwfnt = listOrgOrSource.source_settings.list_directories_with_file_network_traffic;
        if(typeof ldwfnt === "undefined"){
            return {
                isValid: false,
                message: "не заданы директории в которых выполняется фильтрация сет. трафика",
            };
        }
        let newListFolder = ldwfnt.filter((folder) => helpersFunc.checkInputValidation({
            name: "folderStorage",
            value: folder,
        }));
        listOrgOrSource.source_settings.list_directories_with_file_network_traffic = newListFolder;
        
        //проверяем поле description
        if(!helpersFunc.checkInputValidation({ 
            name: "inputDescription", 
            value: listOrgOrSource.description,
        })){
            listOrgOrSource.description = "";
        }
       
        newList.push(listOrgOrSource);
    };

    let errMsg = [];
    let newList = [];
    let processListOrgOrSource = (list) => {
        if(list.length === 0) return;

        list.forEach((item) => {
            if(item.division_or_branch_list_id){
            //организация
                checkOrganization(item, listFieldActivity);
            } else if(item.source_list){
            //подразделение
                checkDivision(item);
            } else {
            //источник
                checkSource(item);   
            }
        });
    };
    
    processListOrgOrSource(listOrgOrSource);

    return { result: newList, errMsg: errMsg };
}

function checkSourceValue(obj, callback) {
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
    if((typeof tt === "undefined") || (tt !== "on")){
        obj.source_settings.transmission_telemetry = "off";
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
}

function insertInformationAboutObjectOrSource(listValideEntity){
    console.log("func 'insertInformationAboutObjectOrSource', START...");
    console.log(listValideEntity);
    
    let organizationPromise = (entity) => {

        console.log(`processed id_organization: ${entity.id_organization}`);

        return new Promise((resolve, reject) => {
            (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelOrganizationName, {
                document: {
                    id: entity.id_organization,
                    date_register: +(new Date),
                    date_change: +(new Date),    
                    name: entity.name,
                    legal_address: entity.legal_address,
                    field_activity: entity.field_activity,
                    division_or_branch_list_id: [],
                }
            }, (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    };

    let divisionPromise = (entity) => {

        console.log(`processed id_division: ${entity.id_division}`);

        return new Promise((resolve, reject) => {
            (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelOrganizationName, {
                query: { "id": entity.id_organization },
                select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
            }, (err, info) => {
                if(err) reject(err);
                else resolve(info);
            });
        }).then((info) => {
            if(info === null){
                console.log(`division '${entity.id_division}' not found`);
            
                return;
            }

            return new Promise((resolve, reject) => {
                //Создаем запись о новом подразделении
                (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelDivisionBranchName, {
                    document: {
                        id: entity.id_division,
                        id_organization: entity.id_organization,
                        date_register: +(new Date),
                        date_change: +(new Date),    
                        name: entity.name,
                        physical_address: entity.physical_address,
                        description: entity.description,
                        source_list: [],
                    }
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }).then(() => {
                return new Promise((resolve, reject) => {
                    //Создаем связь между организацией и подразделением
                    (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelOrganizationName, {
                        query: { 
                            "id": entity.id_organization, 
                            "division_or_branch_list_id": { $ne: entity.id_division },
                        },
                        update:{ $push: {"division_or_branch_list_id": entity.id_division }},
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            });
        });
    };

    let sourcePromise = (entity) => {

        console.log(`processed id_source: ${entity.id_source}`);

        //Создаем запись о новом источнике
        return new Promise((resolve, reject) => {
            (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelDivisionBranchName, {
                query: { "id": entity.id_division },
                select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
            }, (err, info) => {
                if(err) reject(err);
                else resolve(info);
            });
        }).then((info) => {
            if(info === null) {
                console.log(`source '${entity.id_source}' not found`);

                return;
            }

            return new Promise((resolve, reject) => {
                //Создаем связь между организацией и подразделением
                (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelDivisionBranchName, {
                    query: { 
                        "id": entity.id_division, 
                        "source_list": { $ne: entity.id_source },
                    },
                    update:{ $push: {"source_list": entity.id_source }},
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }).then(() => {
                return new Promise((resolve, reject) => {
                    (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelSourcesParameter, {
                        document: {
                            id: entity.id_source,
                            id_division: entity.id_division,
                            source_id: entity.source_id,
                            date_register: +(new Date),
                            date_change: +(new Date),
                            short_name: entity.short_name,
                            network_settings: { 
                                ipaddress: entity.network_settings.ipaddress, 
                                port: entity.network_settings.port, 
                                token_id: entity.network_settings.token_id, 
                            },
                            source_settings: {
                                type_architecture_client_server: entity.source_settings.type_architecture_client_server,
                                transmission_telemetry: (entity.source_settings.transmission_telemetry === "on") ? true: false,
                                maximum_number_simultaneous_filtering_processes: +entity.source_settings.maximum_number_simultaneous_filtering_processes,
                                type_channel_layer_protocol: entity.source_settings.type_channel_layer_protocol,
                                list_directories_with_file_network_traffic: entity.source_settings.list_directories_with_file_network_traffic,
                            },
                            description: entity.description,
                            information_about_app: {
                                version: "не определена",
                                date: "не определено",
                            },
                        }
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    }); 
                });
            });
        });
    };

    let promises = Promise.resolve();
    listValideEntity.forEach((item) => {
        promises = promises.then(() => {
            let organizationID = item.id_organization;
            let divisionID = item.id_division;
            if(organizationID && !divisionID){
                return organizationPromise(item);
            } else if(organizationID && divisionID){
                return divisionPromise(item);
            } else {
                return sourcePromise(item);
            }
        });
    });

    return promises;
}

function checkListEntitiesBasedUserPrivileges(listEntity, userPermission){
    console.log("func 'checkListEntitiesBasedUserPrivileges', START...");

    let addOrg = userPermission.management_organizations.element_settings.create.status;
    let addDivi = userPermission.management_division.element_settings.create.status;
    let addSour = userPermission.management_sources.element_settings.create.status;

    //действие разрешено для всех сущностей
    if(addOrg && addDivi && addSour){

        console.log("действие разрешено для всех сущностей");

        return { entityList: listEntity, errMsg: null };
    }

    //действие запрещено для всех сущностей
    if(!addOrg && !addDivi && !addSour){

        console.log("действие запрещено для всех сущностей");

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

let validList = [
    {
        "id_organization":"nifnienf838f88b383gb83g8883",
        "name":"Организация с непонятным родом деятельности",
        "legal_address":"123555 г. Москва, ул. 1 Мая, д.20, к. 10",
        "field_activity":"кракозябра",
        "division_or_branch_list_id":[]
    },{
        "id_organization":"7036c665164a7a7b3b8243977b5",
        "name":"Новая тестовая организация - первая",
        "legal_address":"123555 г. Москва, ул. 9 Мая, д.120, к. 3",
        "field_activity":"атомная промышленность",
        "division_or_branch_list_id":[]
    },{
        "id_organization":"8b20449203b458a161400921909",
        "name":"Новая тестовая организация - вторая",
        "legal_address":"311453, г. Москва, ул. 1-ого Мая, д. 53, к. 1",
        "field_activity":"органы государственной власти",
        "division_or_branch_list_id":[
            {
                "id_organization":"8b20449203b458a161400921909",
                "id_division":"a3b16680b858c674522142127257",
                "name":"Важное подразделение №1",
                "physical_address":"г. Москва, ул. Щербинка, д. 21",
                "description":"просто примечание",
                "source_list":[
                    {
                        "id_division":"a3b16680b858c674522142127257",
                        "id_source":"bcbc0c6367590771165509575a1a",
                        "source_id":"10022",
                        "short_name":"Short Source Name",
                        "network_settings":{
                            "ipaddress":"32.34.112.45",
                            "port":"13113",
                            "token_id":"608925d25151d2d56c7a936052d8"
                        },
                        "source_settings":{
                            "type_architecture_client_server":"client",
                            "transmission_telemetry":"on",
                            "maximum_number_simultaneous_filtering_processes":"6",
                            "type_channel_layer_protocol":"ip",
                            "list_directories_with_file_network_traffic":[
                                "/folder_1",
                                "/folder_2",
                                "/folder_3"
                            ]
                        },
                        "description":""
                    }
                ]
            }
        ]
    },{
        "id_organization":"cne8h8h828882yfd337fg3g838",
        "id_division":"390ab9a7cb236a677727d31697381",
        "name":"Новое важное подразделение №11",
        "physical_address":"г. Брянск, ул. Ленина, д.56, к. 3",
        "description":"какое то описание",
        "source_list":[
            {
                "id_division":"390ab9a7cb236a677727d31697381",
                "id_source":"3bbaccddcd4cc65352c25d1ba104",
                "source_id":"1034",
                "short_name":"Short Source",
                "network_settings":{
                    "ipaddress":"43.12.5.2",
                    "port":"13113",
                    "token_id":"608925d25151d2d56c7a936052d8"
                },
                "source_settings":{
                    "type_architecture_client_server":"server",
                    "transmission_telemetry":"on",
                    "maximum_number_simultaneous_filtering_processes":"6",
                    "type_channel_layer_protocol":"ip",
                    "list_directories_with_file_network_traffic":[
                        "/new_folder_11",
                        "/new_folder_12",
                        "/new_folder_13",
                        "/new_folder_14"
                    ]
                },
                "description":"options..."
            },{
                "id_division":"390ab9a7cb236a677727d31697381",
                "id_source":"520939710d5a9656d77825b386628",
                "source_id":"1035",
                "short_name":"Short Name",
                "network_settings":{
                    "ipaddress":"34.24.55.2",
                    "port":"111",
                    "token_id":"608925d25151d2d56c7a936052d8"
                },
                "source_settings":{
                    "type_architecture_client_server":"server",
                    "transmission_telemetry":"on",
                    "maximum_number_simultaneous_filtering_processes":"6",
                    "type_channel_layer_protocol":"ip",
                    "list_directories_with_file_network_traffic":[
                        "/directory_1",
                        "/directory_2",
                        "/directory_3",
                        "/directory_4",
                        "/directory_5"
                    ]
                },
                "description":"новое примечание"
            }
        ]
    },{
        "id_division":"dnjdjdnuw82hd8h882h82h8h",
        "id_source":"b9adb0d36a8c78ab78c9c469ac96",
        "source_id":"1090",
        "short_name":"Source N",
        "network_settings":{
            "ipaddress":"53.34.32.45",
            "port":"13113",
            "token_id":"608925d25151d2d56c7a936052d8"
        },
        "source_settings":{
            "type_architecture_client_server":"server",
            "transmission_telemetry":"on",
            "maximum_number_simultaneous_filtering_processes":"6",
            "type_channel_layer_protocol":"ip",
            "list_directories_with_file_network_traffic":[
                "/fold_11",
                "/folde_12",
                "/folder_13"
            ]
        },
        "description":"новое примечание"
    }
];

describe("Тест 1. Запись в СУБД тестовых данных, без обработки объекта содержащего данные", () => {
    it("Должна быть создана иерархия организация -> подразделение -> источник ->, задача должна быть выполненна без ошибок", (done) => {
        async function createElements(){
            //Создание организации
            await (() => {
                return new Promise((resolve, reject) => {

                    console.log("CREATE NEW ORGANIZATION");

                    (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelOrganizationName, {
                        document: {
                            id: hexSumOrg,
                            date_register: +(new Date),
                            date_change: +(new Date),    
                            name: orgName,
                            legal_address: "123452 г. Москва, ул. Каланчевка, д. 89, ст. 1,",
                            field_activity: "космическая промышленность",
                            division_or_branch_list_id: [],
                        }
                    }, err => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            })().catch((err) => {
                throw err;
            });

            //Создание подразделения
            await (() => {
                return new Promise((resolve, reject) => {
                    (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelOrganizationName, {
                        query: { "id": hexSumOrg },
                        select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
                    }, (err, info) => {
                        if(err) reject(err);
                        else resolve(info);
                    });
                }).then((info) => {
                    if(info === null) return;

                    return new Promise((resolve, reject) => {

                        console.log("CREATE NEW DIVISION");

                        //Создаем запись о новом подразделении
                        (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelDivisionBranchName, {
                            document: {
                                id: hexSumDiv,
                                id_organization: hexSumOrg,
                                date_register: +(new Date),
                                date_change: +(new Date),    
                                name: divisionName,
                                physical_address: "г. Смоленск, ул. Зои партизанки, д. 45, к. 2",
                                description: "просто какое то описание",
                                source_list: [],
                            }
                        }, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    }).then(() => {
                        return new Promise((resolve, reject) => {
                            //Создаем связь между организацией и подразделением
                            (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelOrganizationName, {
                                query: { 
                                    "id": hexSumOrg, 
                                    "division_or_branch_list_id": { $ne: hexSumDiv },
                                },
                                update:{ $push: {"division_or_branch_list_id": hexSumDiv }},
                            }, (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                    });
                }).catch((err) => {
                    throw err;
                });
            })().catch((err) => {
                throw err;
            });

            //Создание первого источника
            await (() => {
                console.log("CREATE NEW SOURCE");

                //Создаем запись о новом источнике
                return new Promise((resolve, reject) => {
                    (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelDivisionBranchName, {
                        query: { "id": hexSumDiv },
                        select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
                    }, (err, info) => {
                        if(err) reject(err);
                        else resolve(info);
                    });
                }).then((info) => {
                    if(info === null) return;

                    return new Promise((resolve, reject) => {
                        //Создаем связь между организацией и подразделением
                        (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelDivisionBranchName, {
                            query: { 
                                "id": hexSumDiv, 
                                "source_list": { $ne: hexSumSource },
                            },
                            update:{ $push: {"source_list": hexSumSource }},
                        }, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    }).then(() => {
                        return new Promise((resolve, reject) => {
                            (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelSourcesParameter, {
                                document: {
                                    id: hexSumSource,
                                    id_division: hexSumDiv,
                                    source_id: sourceID,
                                    date_register: +(new Date),
                                    date_change: +(new Date),
                                    short_name: "Test Source",
                                    network_settings: { 
                                        ipaddress: "59.23.4.110", 
                                        port: 13113, 
                                        token_id: "ff24jgj8j328fn8n837ge7g2", 
                                    },
                                    source_settings: {
                                        type_architecture_client_server: "client",
                                        transmission_telemetry: false,
                                        maximum_number_simultaneous_filtering_processes: 5,
                                        type_channel_layer_protocol: "ip",
                                        list_directories_with_file_network_traffic: [
                                            "/test_folder_1",
                                            "/test_folder_2",
                                            "/test_folder_3",
                                        ],
                                    },
                                    description: "дополнительное описание для источника",
                                    information_about_app: {
                                        version: "0.11",
                                        date: "14.03.2020",
                                    },
                                }
                            }, (err) => {
                                if (err) reject(err);
                                else resolve();
                            }); 
                        });
                    });
                }).catch((err) => {
                    throw err;
                });
            })().catch((err) => {
                throw err;
            });

            //Создание второго источника
            await (() => {
                console.log("CREATE NEW SOURCE");
                
                return new Promise((resolve, reject) => {
                    (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelDivisionBranchName, {
                        query: { "id": hexSumDiv },
                        select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
                    }, (err, info) => {
                        if(err) reject(err);
                        else resolve(info);
                    });
                }).then((info) => {
                    if(info === null) return;

                    //Создаем запись о новом источнике
                    return new Promise((resolve, reject) => {
                        (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelSourcesParameter, {
                            document: {
                                id: hexSumSourceTwo,
                                id_division: hexSumDiv,
                                source_id: 1010,
                                date_register: +(new Date),
                                date_change: +(new Date),
                                short_name: "Test Source",
                                network_settings: { 
                                    ipaddress: "210.35.61.120", 
                                    port: 13113, 
                                    token_id: "fnue883fg8gf8g8ssf33f", 
                                },
                                source_settings: {
                                    type_architecture_client_server: "client",
                                    transmission_telemetry: false,
                                    maximum_number_simultaneous_filtering_processes: 5,
                                    type_channel_layer_protocol: "ip",
                                    list_directories_with_file_network_traffic: [
                                        "/test_new_folder_1",
                                        "/test_new_folder_2",
                                        "/test_new_folder_3",
                                    ],
                                },
                                description: "дополнительное описание для источника",
                                information_about_app: {
                                    version: "0.11",
                                    date: "14.03.2020",
                                },
                            }
                        }, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    }).then(() => {
                        return new Promise((resolve, reject) => {
                        //Создаем связь между организацией и подразделением
                            (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelDivisionBranchName, {
                                query: { 
                                    "id": hexSumDiv, 
                                    "source_list": { $ne: hexSumSourceTwo },
                                },
                                update:{ $push: {"source_list": hexSumSourceTwo }},
                            }, (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                    });
                }).catch((err) => {
                    throw err;
                });
            })().catch((err) => {
                throw err;
            });
        }    

        createElements()
            .then(() => {
                done();
            }).catch((err) => {
                expect(err).toBeNull();

                done();
            });
    });
});

describe("Тест 2. Тестируем запись информации о подразделении при отсутствующей организации", () => {
    it("Должен быть получено FALSE, так как такой ОРГАНИЗАЦИ нет в БД", (done) => {
        new Promise((resolve, reject) => {
            (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelOrganizationName, {
                query: { "id": "fnnf838r83g7t8qg8g8fw" },
                select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
            }, (err, info) => {
                if(err) reject(err);
                else resolve(info);
            });
        }).then((info) => {
            if(info === null) return done();

            return new Promise((resolve, reject) => {
                //Создаем связь между организацией и подразделением
                (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelOrganizationName, {
                    query: { 
                        "id": "fnnf838r83g7t8qg8g8fw", 
                        "division_or_branch_list_id": { $ne: "ninnven89nvv838v838b3b83g" },
                    },
                    update:{ $push: {"division_or_branch_list_id": "ninnven89nvv838v838b3b83g" }},
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            }).then(() => {
                return new Promise((resolve, reject) => {

                    console.log("CREATE NEW DIVISION");

                    //Создаем запись о новом подразделении
                    (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelDivisionBranchName, {
                        document: {
                            id: "ninnven89nvv838v838b3b83g",
                            id_organization: "fnnf838r83g7t8qg8g8fw",
                            date_register: +(new Date),
                            date_change: +(new Date),    
                            name: "Не добавляемое подразделение",
                            physical_address: "г. Смоленск, ул. Ленина, д. 14",
                            description: "просто какое то описание",
                            source_list: [],
                        }
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            }).then(() => {
                done();
            }).catch((err) => {
                throw err;
            });
        }).catch((err) => {
            expect(err).toBeNull();

            done();
        });
    });
});
      
describe("Тест 3. Валидация тестового объекта с информацией по организациям и источникам", () => {
    it("Должен быть получен новый, проверенный список организаций, подразделений и источников", () => {
        let newListObject = getValidObjectOrganizationOrSource(validList, globalObject.getData("commonSettings", "listFieldActivity")); 

        /*
        console.log(newListObject);
        console.log("-------------");
        console.log(JSON.stringify(newListObject));
        */

        expect(newListObject.result.length).not.toEqual(0);
        expect(newListObject.errMsg.length).toEqual(0);
    });
});

describe("Тест 3.1. Валидация тестового объекта с информацией по организациям и источникам", () => {
    it("Должен быть получен новый, проверенный список, должны быть некоторые ошибки", () => {
        validList.push({
            "id_organization":"nifnienf838f88b383gb83g8883",
            "name":"Организация REEc с непонятным родом деятельности",
            "legal_address":"123555 г. Москва, ул. 1 Мая, д.20, ***к. 10",
            "field_activity":"кракозябра",
            "division_or_branch_list_id":[]
        });

        validList.push({
            "id_organization":"8b20449203b458a161400921909",
            "name":"Яндекс организация - вторая",
            "legal_address":"311453, г. Москва, ул. 1-ого Мая, д. 53, к. 1",
            "field_activity":"органы государственной власти",
            "division_or_branch_list_id":[
                {
                    "id_organization":"8b20449203b458a161400921909",
                    "id_division":"a3b16680b858c674522142127257",
                    "name":"В***ажное подразделение №1",
                    "physical_address":"г. Москва, ул. Щербинка, д. 21",
                    "description":"просто примечание",
                    "source_list":[]
                }]
        });
        
        let { result: newListObject, errMsg } = getValidObjectOrganizationOrSource(validList, globalObject.getData("commonSettings", "listFieldActivity")); 

        //        console.log(newListObject);
        console.log("- Тест 3.1. ----- newObjEntity -------");
        console.log(JSON.stringify(newListObject));
        console.log("ERROR");
        console.log(errMsg);

        expect(newListObject.length).not.toEqual(0);
        expect(errMsg.length).not.toEqual(0);
    });
});

/*
describe("Тест 4. Загрузка, полученного после валидации списка, в БД", () => {
    it("Должен быть успешно загружен в БД весь список елементов, у которого дочерние елементы имеют родительские. Ошибок быть не должно.", (done) => {
        new Promise((resolve, reject) => {
            //заранее создаем тестовую организацию 
            console.log("CREATE NEW ORGANIZATION");

            (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelOrganizationName, {
                document: {
                    id: "cne8h8h828882yfd337fg3g838",
                    date_register: +(new Date),
                    date_change: +(new Date),    
                    name: orgName,
                    legal_address: "123452 г. Москва, ул. Каланчевка, д. 89, ст. 1,",
                    field_activity: "космическая промышленность",
                    division_or_branch_list_id: [],
                }
            }, err => {
                if (err) reject(err);
                else resolve();
            });
        }).then(() => {
            //заранее создаем тестовое подразделение
            return new Promise((resolve, reject) => {
                (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelOrganizationName, {
                    query: { "id": "cne8h8h828882yfd337fg3g838" },
                    select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
                }, (err, info) => {
                    if(err) reject(err);
                    else resolve(info);
                });
            }).then((info) => {
                if(info === null) return;

                return new Promise((resolve, reject) => {
                    //Создаем запись о новом подразделении
                    (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelDivisionBranchName, {
                        document: {
                            id: "dnjdjdnuw82hd8h882h82h8h",
                            id_organization: "cne8h8h828882yfd337fg3g838",
                            date_register: +(new Date),
                            date_change: +(new Date),    
                            name: divisionName,
                            physical_address: "г. Смоленск, ул. Зои партизанки, д. 45, к. 2",
                            description: "просто какое то описание",
                            source_list: [],
                        }
                    }, (err) => {
                        if (err) reject(err);
                        else resolve();
                    });
                }).then(() => {
                    return new Promise((resolve, reject) => {
                        //Создаем связь между организацией и подразделением
                        (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelOrganizationName, {
                            query: { 
                                "id": "cne8h8h828882yfd337fg3g838", 
                                "division_or_branch_list_id": { $ne: "dnjdjdnuw82hd8h882h82h8h" },
                            },
                            update:{ $push: {"division_or_branch_list_id": "dnjdjdnuw82hd8h882h82h8h" }},
                        }, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    });
                });
            });
        }).then(() => {
            return insertInformationAboutObjectOrSource(getValidObjectOrganizationOrSource(validList, globalObject.getData("commonSettings", "listFieldActivity")).result);
        }).then(() => {
            console.log("INSERTED SUCCESS!!!");
            expect(true).toEqual(true);

            done();
        }).catch((err) => {
            console.log(`ERROR: ${err.toString()}`);
            expect(err).toBe(null);

            done();
        });   
        //expect((()=>{throw new Error("my error test");})).not.toThrow();
        
    });
});
*/

describe("Тест 5. Получить весь список сущностей из БД", () => {     
    it("Должен быть получен весь список сущностей из БД", (done) => {
        async.parallel({
            shortListSource: (callbackParallel) => {
                (require("../../middleware/mongodbQueryProcessor")).querySelect(
                    require("../../controllers/models").modelSourcesParameter, { 
                        isMany: true,
                        select: { 
                            _id: 0, 
                            __v: 0, 
                            description: 0,
                            date_register: 0, 
                            source_settings : 0, 
                            network_settings: 0,
                        },
                    }, (err, list) => {
                        if(err) callbackParallel(err);
                        else callbackParallel(null, list);
                    });
            },
            shortListDivision: (callbackParallel) => {
                (require("../../middleware/mongodbQueryProcessor")).querySelect(
                    require("../../controllers/models").modelDivisionBranchName, { 
                        isMany: true,
                        select: { 
                            _id: 0, 
                            __v: 0, 
                            description: 0,
                            date_change:0,
                            date_register: 0, 
                            physical_address: 0,
                        },
                    }, (err, list) => {
                        if(err) callbackParallel(err);
                        else callbackParallel(null, list);
                    });
            },
            shortListOrganization: (callbackParallel) => {
                (require("../../middleware/mongodbQueryProcessor")).querySelect(
                    require("../../controllers/models").modelOrganizationName, { 
                        isMany: true,
                        select: { 
                            _id: 0,
                            __v: 0, 
                            date_change:0,
                            date_register: 0, 
                            legal_address: 0,
                        },
                    }, (err, list) => {
                        if(err) callbackParallel(err);
                        else callbackParallel(null, list);
                    });
            },
        }, (err, listEntity) => {
            console.log(`ERROR: ${err}`);
            console.log(`LIST: ${JSON.stringify(listEntity)}`); 

            expect(err).toBe(null);
            expect(listEntity.shortListSource.length).toEqual(4);

            done();
        });
    });

    /*    it("Должен быть получено FALSE, так как такого ИСТОЧНИКА нет в БД", () => {
    
    });*/

});

/**
 *      Все тесты прошли успешно, данные по организациям, подразделениям
 *  и источникам загружаются успешно. Связи меду ними устанавливаются. 
 *  Теперь можно переходить к написанию основной части backend отвечающей
 *  за обработку данных по организациям и источникам.
 *  Для этого использовать функции:
 *  валидации - getValidObjectOrganizationOrSource
 *  insert to DB - insertInformationAboutObjectOrSource
 */

describe("Тест 6. Получить информацию по источнику, организации и подразделению", () => {   
    it("Должен быть успешно найдена информация об источнике, при этом ошибок быть не должно", (done) => {
        new Promise((resolve, reject) => {
            (require("../../middleware/mongodbQueryProcessor")).querySelect(
                require("../../controllers/models").modelSourcesParameter, { 
                    query: { id: "bcbc0c6367590771165509575a1a" },
                    select: { _id: 0,  __v: 0 },
                }, (err, list) => {
                    if(err) reject(err);
                    else resolve(list);
                });
        }).then((sourceInfo) => {
            return new Promise((resolve, reject) => {
                (require("../../middleware/mongodbQueryProcessor")).querySelect(
                    require("../../controllers/models").modelDivisionBranchName, { 
                        query: { id: sourceInfo.id_division },
                        select: { _id: 0,  __v: 0 },
                    }, (err, list) => {
                        if(err) reject(err);
                        else resolve({ source: sourceInfo, division: list });
                    });
            });
        }).then((objInfo) => {
            return new Promise((resolve, reject) => {
                (require("../../middleware/mongodbQueryProcessor")).querySelect(
                    require("../../controllers/models").modelOrganizationName, { 
                        query: { id: objInfo.division.id_organization },
                        select: { _id: 0,  __v: 0 },
                    }, (err, list) => {
                        if(err) reject(err);
                
                        objInfo.organization = list;
                        resolve(objInfo);
                    });
            });
        }).then((objInfo) => {
            console.log(objInfo);

            expect(objInfo.source.source_id).toEqual(10022);
            done();
        }).catch((err) => {
            expect(err).toBeNull();

            done();
        });
    });
});

describe("Тест 7. Проверка функции валидации параметров источника при его изменении", () => {   
    it("Если объект валидный то ошибок быть не должно", (done) => {
        let testObj = {
            network_settings: {
                ipaddress: "34.24.55.2",
                port: 111,
                token_id: "608925d25151d2d56c7a936052d8"
            },
            source_settings: {
                list_directories_with_file_network_traffic: [
                    "/directory_1",
                    "/directory_2",
                    "/directory_3",
                    "/directory_4",
                    "/directory_5"
                ],
                type_architecture_client_server: "server",
                transmission_telemetry: true,
                maximum_number_simultaneous_filtering_processes: 6,
                type_channel_layer_protocol: "ip"
            },
            id: "520939710d5a9656d77825b386628",
            source_id: 1035,
            date_register: 1584621223950,
            date_change: 1584621223950,
            short_name: "Short Name",
            description: ""
        };
        
        checkSourceValue(testObj, (err, newTestObj) => {
            if(err) {
                console.log(err.toString());
            }

            console.log("___________________");
            console.log(newTestObj);
            console.log("___________________");

            expect(err).toBeNull();

            done();
        });    
    });
});

describe("Тест 8. Проверка прав пользователя на добавление различных типов сущьностей", () => {  
    let listEntity = [{
        id_organization: "517b071ab6715d91d3756498245746",
        name: "Первая коммерческая организация",
        legal_address: "мдмщ щмащ щмщаищща",
        field_activity: "коммерческая деятельность"
    }, {
        id_organization: "517b071ab6715d91d3756498245746",
        id_division: "b6a6b6d72615dda77b8238b2b105",
        name: "Офис №1",
        physical_address: "вуа  ау  аьшщуашшу",
        description: ""
    }, {
        id_division: "b6a6b6d72615dda77b8238b2b105",
        id_source: "4bb063441dc1936d38700a022d1a8",
        source_id: "11001",
        short_name: "Office №1",
        network_settings: {
            ipaddress: "32.14.41.3",
            port: "11321",
            token_id: "8ca525d77882b37a2d2935c75474"
        },
        source_settings: {
            type_architecture_client_server: "client",
            transmission_telemetry: "off",
            maximum_number_simultaneous_filtering_processes: 5,
            type_channel_layer_protocol: "ip",
            list_directories_with_file_network_traffic: ["/folder_1", "/folder_2"]
        },
        description: ""
    }];
    
    let userPermission = {
        management_organizations: {
            element_settings: { 
                create: {
                    id:"933da4bb4eed4eef2c3034a09738323f",
                    status: true,
                    description:"создание"
                }, 
                edit: {}, delete: {}},
            id: "9c2b9e65157a833455ff4da6b29b4fa4",
            name: "управление организациями"
        },
        management_division: {
            element_settings: { 
                create: {
                    id:"933da4bb4egfdiifdic3034a09738323f",
                    status: true,
                    description:"создание"
                }, 
                edit: {}, delete: {}},
            id: "98fb4a147fb46af6eb8020b64feab1c0",
            name: "управление подразделениями"
        },
        management_sources: {
            element_settings: { 
                create: {
                    id:"9sfsfa4bb4eed4eef2c3034a09738323f",
                    status: true,
                    description:"создание"
                }, 
                edit: {}, delete: {}},
            id: "828c59969fb6ca31c003ec77aa074d59",
            name: "управление источниками"
        }
    }; 

    it("Должен быть получен список сущностей типы которых может добавлять пользователь", () => {
        let { entityList, errMsg } = checkListEntitiesBasedUserPrivileges(listEntity, userPermission);

        console.log("----- Новый список сущностей ----");
        console.log(entityList);
        console.log("===== Ошибки =====");
        console.log(errMsg);

        expect(errMsg).toBeNull();
    });
});


describe("Тест 9. Проверка вставки списка организаций", () => {
    it("Список должен быть успешно вставлен, ошибки быть не должно", (done) => {
        (require("../../middleware/mongodbQueryProcessor")).queryInsertMany(require("../../controllers/models").modelOrganizationName, [
            {
                id: "foe3ej9er9r9b9rf9b9fu9dbu9f",
                date_register: +(new Date),
                date_change: +(new Date),    
                name: "Test 1 name",
                legal_address: "Test 1 address",
                field_activity: "Test 1 activity",
                division_or_branch_list_id: [],
            },
            {
                id: "248438r838r83vr8fv38vr8f83v8",
                date_register: +(new Date),
                date_change: +(new Date),    
                name: "Test 2 name",
                legal_address: "Test 2 address",
                field_activity: "Test 2 activity",
                division_or_branch_list_id: [],
            },
            {
                id: "rj99398hr93hrf9h399fh93h9f93",
                date_register: +(new Date),
                date_change: +(new Date),    
                name: "Test 3 name",
                legal_address: "Test 3 address",
                field_activity: "Test 3 activity",
                division_or_branch_list_id: [],
            }
        ], (err, doc) => {
            if(err) console.log(`ERROR: ${err.toString()}`);

            console.log("----------- doc ---------");
            console.log(doc);

            expect(err).toBeNull();
        });
    });
});

/*

    id: { type: String, index: true, unique: true },
    date_register: Number,
    date_change: Number,    
    name: String,
    legal_address: String,
    field_activity: String,
    division_or_branch_list_id: [String],

    describe("Тест 4. Загрузка тестового объекта в БД", () => {

});

/**
 *  !!! НЕ ЗАБЫТЬ что я создал отдельную ветку current_development и
 * сейчас нахожусь в ней !!!
 * 
 */


/*describe("Тест 1. Проверка обработки объекта с данными с помощью регулярного выражения", () => {
    it("Должен быть получено TRUE на принятое валидное выражение", () => {
    
    });
});

describe("Тест 2. Проверка функций взаимодействующих с СУБД", () => {
    let userLogin = "jasmine111";
    let hexSum = (require("../../libs/helpers/createUniqID")).getMD5(`user_name_${userLogin}`);

    it("Запрос пользователя по логину (ПОЛЬЗОВАТЕЛь НАЙДЕН)", (done) => {
    });
});*/
