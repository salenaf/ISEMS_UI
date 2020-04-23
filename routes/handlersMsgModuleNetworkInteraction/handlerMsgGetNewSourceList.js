"use strict";

const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");

/**
 * Обрабатываем запрос актуального списка источников
 * получаемый от модуля ISEMS-NIH_master (запрос типа 'get new source list')
 * 
 * @param {*} - msg
 */
module.exports = async (msg) => {
    try {
        let sourceList = await getSourceList();
        let optionsJSON = await converSourceListToJSONOptions(sourceList); 

        globalObject.getData("descriptionAPI", "networkInteraction", "connection").sendMessage({
            msgType: "information",
            msgSection: "source control",
            msgInstruction: "send new source list",
            taskID: require("../../libs/helpers/helpersFunc").getRandomHex(),
            options: { sl: optionsJSON },
        });

    } catch(err){
        writeLogFile("error", `${err.toString()} (func 'handlerMsgGetNewSourceList')`);
    }
};

//получаем из БД список источников
function getSourceList(){
    return new Promise((resolve, reject) => {
        require("../../middleware/mongodbQueryProcessor").querySelect(require("../../controllers/models").modelSourcesParameter, {
            isMany: true,
            select: { _id: 0, id: 0, __v: 0, id_division: 0, information_about_app: 0, date_register: 0, date_change: 0 },
        }, (err, sourceList) => {
            if(err) reject(err);
            else resolve(sourceList);
        });
    });
}

function converSourceListToJSONOptions(sourceList){
    return Promise.resolve(sourceList.map((item) => {
        let tacs = item.source_settings.type_architecture_client_server;

        return {
            id: item.source_id,
            at: "none",
            arg: {
                ip: item.network_settings.ipaddress,
                t: item.network_settings.token_id,
                sn: item.short_name,
                d: item.description,
                s: {
                    as: (tacs === "server"),
                    p: item.network_settings.port,
                    et: item.source_settings.transmission_telemetry,
                    mcpf: item.source_settings.maximum_number_simultaneous_filtering_processes,
                    tan: item.source_settings.type_channel_layer_protocol,
                    sf: item.source_settings.list_directories_with_file_network_traffic,
                },
            },
        };
    })); 
}