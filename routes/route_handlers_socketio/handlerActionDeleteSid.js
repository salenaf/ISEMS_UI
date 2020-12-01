"use strict";

const fs = require("fs");
const path = require("path");
const showNotify = require("../../libs/showNotify");
const writeLogFile = require("../../libs/writeLogFile");

/**
 * Модуль для обновления SID в базе данных
 * 
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {
    const handlers = {
        "delete value SID":  deleteSID,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};


function processing(data){
    // eslint-disable-next-line no-useless-catch
    try{
        let mongooseModel = require("../../controllers/models").modelSOARules;
        let requireMong = (require("../../middleware/mongodbQueryProcessor"));

        return new Promise((resolve,reject) => {
            requireMong.queryDelete(
                mongooseModel, {
                    query: { sid: data.checkSID },
                }, 
                (err,doc) => {
                    if(err) reject(err);
                    else resolve(doc); 
                }
            );
        });
    } catch(err){
        throw err;
    }
}


function  deleteSID(socketIo, data){
    console.log("func ' deleteSID', START...");
    console.log(data);
   
    processing(data).then(() => {
        console.log("ОK");
        showNotify({
            socketIo: socketIo,
            type: "success",
            message: "Успешно удалено"
        });
        socketIo.emit("result delete value SID", { info: "insert OK" });
    }).catch((err) => {
        //console.log(err);
        console.log(`--------> ${err}`);
            
        writeLogFile("error", `function ' deleteSID': ${err.toString()}`);
        socketIo.emit("SID delete result", { info: `insert ${err.toString()}` });
    });
}