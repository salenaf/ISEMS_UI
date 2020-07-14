"use strict";

const async = require("async");

const globalObject = require("../../configure/globalObject");
const writeLogFile = require("../../libs/writeLogFile");
const checkAccessRightsPage = require("../../libs/check/checkAccessRightsPage");

function testAddProcessedTasks(){

    globalObject.setData("tasks", "networkInteractionTaskList", "ifnefj939999g9gfffge3", {
        createDate: +(new Date),
        typeTask: "filtration",
        statusTask: "execute",
        userLogin: "user login test",
        userName: "user name test",
        sourceID: 11111,
        sourceName: "source name Test",
    });
    globalObject.setData("tasks", "networkInteractionTaskList", "fievig909j99g9g99gff", {
        createDate: +(new Date),
        typeTask: "download",
        statusTask: "execute",
        userLogin: "user login test",
        userName: "user name test",
        sourceID: 11111,
        sourceName: "source name Test",
    });
    
}

/**
 * Модуль формирующий страницу на которой реализовано управление
 * модулем сетевого взаимодействия
 * 
 * @param {*} req
 * @param {*} res
 * @param {*} objHeader
 */
module.exports = function(req, res, objHeader) {
    testAddProcessedTasks();

    async.parallel({
        permissions: (callback) => {
            checkAccessRightsPage(req, (err, result) => {
                if (err) callback(err);
                else callback(null, result);
            });
        },
        mainInformation: (callback) => {

            callback(null, {});
        
        },
        widgetsInformation: (callback) => {
            let numConnect = 0,
                numDisconnect = 0;

            let listSources = globalObject.getData("sources");
            for(let source in listSources){
                if(listSources[source].connectStatus){
                    numConnect++;
                } else {
                    numDisconnect++;
                }
            }

            callback(null, {
                numConnect: numConnect,
                numDisconnect: numDisconnect,
            });
        }
    }, (err, result) => {
        if (err) {
            writeLogFile("error", err.toString());
            res.render("menu/network_interaction", {
                header: objHeader,
                userPermissions: {},
                mainInformation: {},
            });

            return;
        }
        
        let userPermissions = result.permissions.group_settings;
        let readStatus = userPermissions.menu_items.network_interaction.status;

        if (readStatus === false) return res.render("403");

        console.log("func 'networkInteraction'");
        console.log(result.widgetsInformation);

        res.render("menu/network_interaction", {
            header: objHeader,
            listItems: {
                connectionModules: {
                    moduleNI: globalObject.getData("descriptionAPI", "networkInteraction", "connectionEstablished")
                },
                userPermissions: userPermissions.management_network_interaction.element_settings,
                mainInformation: result.mainInformation,
                widgetsInformation: result.widgetsInformation,
                listSources: globalObject.getData("sources"),
            },
        });
    });
};