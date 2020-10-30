"use strict";

const helpersFunc = require("../../helpers/helpersFunc");
const globalObject = require("../../../configure/globalObject");

/**
 * Модуль выполняющий валидацию объекта с новыми сущностями (организациями, 
 * подразделениями и источниками). Данный объект приходит от пользователя UI
 *
 * @param {*} listOrgOrSource - объект с новыми сущностями
 */
module.exports = function(listOrgOrSource) {
    let listFieldActivity = globalObject.getData("commonSettings", "listFieldActivity");

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

        let tclp = new Set(["ip", "pppoe", "vlan + pppoe", "pppoe + vlan"]);
        if(typeof listOrgOrSource.source_settings.type_channel_layer_protocol === "undefined"){
            listOrgOrSource.source_settings.type_channel_layer_protocol = "ip";    
        }
        if(!tclp.has(listOrgOrSource.source_settings.type_channel_layer_protocol)){
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
};