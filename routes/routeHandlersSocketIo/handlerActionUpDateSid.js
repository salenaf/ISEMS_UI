"use strict";

const fs = require("fs");
const path = require("path");

const writeLogFile = require("../../libs/writeLogFile");

/**
 * Модуль обработчик файлов поступающих из User Interface
 * 
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(socketIo) {
    const handlers = {
        "update value SID": updateSID,
    };

    for (let e in handlers) {
        socketIo.on(e, handlers[e].bind(null, socketIo));
    }
};

function  wordOut(strBody, keywordStart, keywordEnd, posNull =0 ){
    let posStart = 0, posEnd = 0;
    let resultStr = null ;

    posStart = strBody.indexOf(keywordStart , posNull);
    if(posStart!=-1){
        posEnd = strBody.indexOf(keywordEnd, posStart+1);
        if(posEnd!=-1){
            resultStr = strBody.slice(posStart + keywordStart.length , posEnd) ;
        }
    // console.log (`pos1 = ${posStart}; pos2 = ${posEnd}; resultStr = ${resultStr}`);
    }
    return resultStr;
}

function parser(body){
    let element;

    let a_classType,b_sid,c_msg;
   
    let mongooseModel = require("../../controllers/models").modelSOARules;

    a_classType = wordOut(body, "classtype:",";"); 
    b_sid       = wordOut(body, "sid:",";"); 
    c_msg       = wordOut(body, "msg:",";"); 
        
    if(( a_classType !=null)&(b_sid!=null)&(c_msg!=null)) {
               
        let check = c_msg.indexOf("\"");
        if(check != -1)
        {
            c_msg = c_msg.slice(c_msg.indexOf("\"")+1, c_msg.indexOf("\"", 3));
        }//new mongooseModel(
        element =  {
            sid: b_sid,
            classType: a_classType,
            msg: c_msg,
            body: body,
        };
    }
    //return Promise.resolve(element);
    return element;
}

function processing(data){
    // eslint-disable-next-line no-useless-catch
    try{
        
        let newRule = parser(data.updateBody);
        let mongooseModel = require("../../controllers/models").modelSOARules;
        let requireMong = (require("../../middleware/mongodbQueryProcessor"));

        return new Promise((resolve,reject) => {
            requireMong.queryUpdate(
                mongooseModel, {
                    query: { sid: data.checkSID },
                    update:{ 
                        msg:  newRule.msg,
                        classType: newRule.classType,
                        body: newRule.body,
                    }}, 
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
/*
async function processing(data){
 
    // eslint-disable-next-line no-useless-catch
    try{

        let listRules = await parser(data);
        await ((listRules ) => {
            return new Promise((resolve, reject) => {
                (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelSOARules, {
                    query: { sid: listRules.sid },
                    update: {
                        sid: listRules.sid,
                        type: listRules.type,
                        body: listRules.body,
                    },
                }, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
        })(listRules);
    } catch(err){
        throw err;
    }
}
*/

function updateSID(socketIo, data){
    console.log("func 'updateSID', START...");
    console.log(data);
   
       
    processing(data).then(() => {
        console.log("ОK");

        socketIo.emit("result update value SID", { info: "insert OK" });
    }).catch((err) => {
        //console.log(err);
        console.log(`--------> ${err}`);
            
        writeLogFile("error", `function 'receivedFilesRulesSOA': ${err.toString()}`);

        socketIo.emit("SID upload result", { info: `insert ${err.toString()}` });
    });
   
    
}