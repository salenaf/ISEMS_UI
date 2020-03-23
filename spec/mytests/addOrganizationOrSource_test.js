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

afterAll(async() => {
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
});

function getValidObjectOrganizationOrSource(listOrgOrSource, listFieldActivity) {
    console.log("func 'getValidObjectOrganizationOrSource', START...");
    
    let checkInputValidation = (elem) => {
        let objSettings = {
            "hostID": new RegExp("^[0-9]{2,}$"),
            "shortNameHost": new RegExp("^[a-zA-Z0-9_№\"\\-\\s]{3,}$"),
            "fullNameHost": new RegExp("^[a-zA-Zа-яА-ЯёЁ0-9_№\"\\-\\s\\.,]{5,}$"),
            "ipaddress": new RegExp("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)[.]){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$"),
            "port": new RegExp("^[0-9]{1,5}$"),
            "countProcess": new RegExp("^[0-9]{1}$"),
            "intervalTransmission": new RegExp("^[0-9]{1,}$"),
            "folderStorage": new RegExp("^[\\w\\/_-]{3,}$"),
            "inputDescription": new RegExp("^[\\w\\sа-яА-ЯёЁ().,@№\"!?_-]$"),
            "stringRuNumCharacter": new RegExp("^[а-яА-ЯёЁ0-9\\s.,№-]+$"),
            "stringAlphaRu": new RegExp("^[а-яА-ЯёЁ\\s]{4,}$"),
            "stringAlphaNumEng": new RegExp("^[a-zA-Z0-9_-]{4,}$"),
            "stringPasswd": new RegExp("^[a-zA-Z0-9!@#$%^&*()?]{7,}$"),
        };
        let pattern = objSettings[elem.name];

        if(typeof pattern === "undefined"){
            return false;
        }

        if (elem.name === "port") {
            if (!(0 <= elem.value && elem.value < 65536)) return false;
        }
        if (elem.name === "intervalTransmission" && (elem.value < 10)) return false;
        return (!pattern.test(elem.value)) ? false : true;
    };

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
                errMsg.push(new Error("в объекте с информацией об организации отсутствуют некоторые поля"));

                return;
            }

            if(!checkInputValidation({
                name: pattern[elemName].namePattern,
                value: listOrgOrSource[elemName],
            })){
                errMsg.push(new Error(pattern[elemName].messageError));

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
                errMsg.push(new Error("в объекте с информацией о подразделении отсутствуют некоторые поля"));
                
                return;
            }

            if(!checkInputValidation({
                name: pattern[elemName].namePattern,
                value: listOrgOrSource[elemName],
            })){
                errMsg.push(pattern[elemName].messageError);

                return;
            }
        }

        //проверяем поле description
        let description = ""; 
        if(checkInputValidation({ 
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
                errMsg.push(new Error("отсутствует некоторая информацией об источнике"));

                return;
            }
       
            if(!checkInputValidation({
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
                errMsg.push(new Error("отсутствует некоторая информация, необходимая для осуществления сетевого соединения с источником"));
                
                return;
            }

            if(!checkInputValidation({
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
        let newListFolder = ldwfnt.filter((folder) => checkInputValidation({
            name: "folderStorage",
            value: folder,
        }));
        listOrgOrSource.source_settings.list_directories_with_file_network_traffic = newListFolder;
        
        //проверяем поле description
        if(!checkInputValidation({ 
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

describe("Тест 5. Получить весь список сущьностей из БД", () => {     
    it("Должен быть получен весь список сущьностей из БД", (done) => {
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



/*
describe("Тест 4. Загрузка тестового объекта в БД", () => {

    
        it("Должен быть получено FALSE, так как такого ПОДРАЗДЕЛЕНИЯ нет в БД", () => {
        
        });
    
        it("Должен быть получено FALSE, так как такого ИСТОЧНИКА нет в БД", () => {
        
        });
    
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




/*
    let orgName = "Новая организация";
    let hexSumOrg = (require("../../libs/helpers/createUniqID")).getMD5(`organization_name_${orgName}`);

    it("Должен быть получено TRUE, если название ОРГАНИЗАЦИ есть в БД", (done) => {
        new Promise((resolve, reject) => {

            console.log("CREATE NEW ORGANIZATION");

            //Создаем новую запись об организации
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
        }).then(() => {
            return new Promise((resolve, reject) => {

                console.log("GET INFORMATION ABOUT ORGANIZATION");

                //Выполняем поиск огранизации по ее ID
                (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelOrganizationName, {
                    document: { id: hexSumOrg }
                }, (err, info) => {
                    if(err) reject(err);
                    else resolve(info);
                });
            });
        }).then((info) => {

            console.log(`INFO ORGANIZATION: '${info}'`);

            expect(info.name).toEqual(orgName);

            done();
        }).catch((err) => {
            expect(err).toBeNull();

            done();
        });
    });

    let divisionName = "Новое подразделение";
    let hexSumDiv = (require("../../libs/helpers/createUniqID")).getMD5(`organization_name_${divisionName}`);

    it("Должен быть получено TRUE, если название ПОДРАЗДЕЛЕНИЯ есть в БД", (done) => {
        new Promise((resolve, reject) => {

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
        }).then(() => {
            return new Promise((resolve, reject) => {

                console.log("GET INFORMATION ABOUT DIVISION");

                //Выполняем поиск инофрмации о подразделении по его ID
                (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelDivisionBranchName, {
                    document: { id: hexSumDiv }
                }, (err, info) => {
                    if(err) reject(err);
                    else resolve(info);
                });
            });
        }).then(info => {

            console.log(`INFO DIVISION: '${info}'`);

            expect(info.name).toEqual(divisionName);

            done();
        }).catch(err => {
            expect(err).toBeNull();

            done();
        });
    });

    let sourceID = 1001;
    let hexSumSource = (require("../../libs/helpers/createUniqID")).getMD5(`organization_name_${sourceID}`);

    it("Должен быть получено TRUE, если название ИСТОЧНИКА есть в БД", (done) => {
        new Promise((resolve, reject) => {

            console.log("CREATE NEW SOURCE");

            //Создаем запись о новом источнике
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
        }).then(() => {
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
            });
        }).then(() => {
            return new Promise((resolve, reject) => {

                console.log("GET INFORMATION ABOUT SOURCE");

                //Выполняем поиск инофрмации о подразделении по его ID
                (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelSourcesParameter, {
                    document: { id: hexSumDiv }
                }, (err, info) => {
                    if(err) reject(err);
                    else resolve(info);
                });
            });
        }).then(info => {

            console.log(`INFO SOURCE: '${info}'`);

            expect(info.source_id).toEqual(sourceID);

            done();
        }).catch(err => {
            expect(err).toBeNull();

            done();
        });
    });
*/
