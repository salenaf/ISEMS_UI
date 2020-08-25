"use strict";

const helpersFunc = require("../../helpers/helpersFunc");

/**
 * Модуль выполняющий валидацию параметров фильтрации полученных от пользователя UI
 *
 * @param {*} filteringParameters - объект с параметрами фильтрации
 */
module.exports = function(filteringParameters) {
    let checkNetworkPortIP = (section, type) => {
        let validInput = { 
            any: [],
            src: [],
            dst: [],
        };

        for(let d in filteringParameters.inputValue[section]){
            validInput[d] = filteringParameters.inputValue[section][d].filter((item) => {
                return helpersFunc.checkInputValidation({ 
                    name: type, 
                    value: item,
                });
            });
        }

        return validInput;
    };

    let checkExistInputValue = (inputValue) => {
        let isEmpty = true;

        done:
        for(let et in inputValue){
            for(let d in inputValue[et]){
                if(Array.isArray(inputValue[et][d]) && inputValue[et][d].length > 0){
                    isEmpty = false;

                    break done;  
                }
            }
        }

        return isEmpty;
    };

    //проверяем наличие id источника
    if(!helpersFunc.checkInputValidation({ 
        name: "hostID", 
        value: filteringParameters.source,
    })){
        return {
            filteringParameters: {}, 
            isValid: false, 
            errorMsg: "Принят некорректный идентификатор источника." 
        };
    }

    //проверяем время
    for(let dt in filteringParameters.dateTime){
        if(!helpersFunc.checkInputValidation({
            name: "intervalTransmission",
            value: filteringParameters.dateTime[dt],
        })){
            return { 
                filteringParameters: {}, 
                isValid: false, 
                errorMsg: "Принято некорректное значение времени." 
            };
        }
    }
    if(+filteringParameters.dateTime.start > +filteringParameters.dateTime.end){
        return { 
            filteringParameters: {}, 
            isValid: false, 
            errorMsg: "Начальное дата и время не может быть больше конечного." 
        };
    }

    let newInputValue = {
        ip: checkNetworkPortIP("ip", "ipaddress"),
        nw: checkNetworkPortIP("nw", "network"),
        pt: checkNetworkPortIP("pt", "port"),
    };

    //проверяем наличие хотябы одного параметра в inputValue
    if(checkExistInputValue(newInputValue)){
        return { 
            filteringParameters: {}, 
            isValid: false, 
            errorMsg: "Хотя бы один из параметров ip адрес, сеть или порт должен быть заполнен." 
        };
    }

    return { 
        filteringParameters: {
            source: +filteringParameters.source,
            dateTime: { 
                start: Math.trunc(+filteringParameters.dateTime.start / 1000),
                end: Math.trunc(+filteringParameters.dateTime.end / 1000),
            },
            networkProtocol: ((filteringParameters.networkProtocol === "tcp") || (filteringParameters.networkProtocol === "udp")) ? filteringParameters.networkProtocol : "any",
            inputValue: newInputValue,
        }, 
        isValid: true, 
        errorMsg: "" 
    };
};