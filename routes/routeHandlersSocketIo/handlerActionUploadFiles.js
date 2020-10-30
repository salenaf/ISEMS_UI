"use strict";

const fs = require("fs");
const path = require("path");

const writeLogFile = require("../../libs/writeLogFile");

/**
 * Модуль обработчик файлов поступающих из User Interface
 * 
 * @param {*} socketIo 
 */
module.exports.addHandlers = function(ss, socketIo) {
    const handlers = {
        "uploading files with SOA rules": receivedFilesRulesSOA,
    };

    for (let e in handlers) {
        ss(socketIo).on(e, handlers[e].bind(null, socketIo));
    }
};

function  wordOut(strBody, keywordStart, keywordEnd, posNull =0 ){
    // let strBody ="alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (  msg:\"Downloader.MediaDrug.HTTP.C&C\"; flow:established,to_server;  content:\"GET\"; http_method; content:\"advert_key=\"; http_uri; fast_pattern;   content:\"app=\"; http_uri;  content:\"oslang=\"; http_uri; classtype:trojan-activity; sid:35586741; rev:0;)";
    /*
    let keyword1= "classtype";
    let keywordEnd1 = ";";              */

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

async function readFileRule(fileName){
    
    return new Promise((resolve,reject) => {
        fs.readFile(fileName, "utf8", (err, data) => {
            if(err) reject(err);
            else resolve(data); 
        });
    });
}

function parser(data){
    //let  possStart = -1;
    let arrList = [];
    let element ;
    //let n = Number(data.length);
    // console.log(`${n}`); 
    let a_classType,b_sid,c_msg;
    let strBody = "";
    let listRules = data.split("\n");
    
    //let mongooseModel = require("../../controllers/models").modelSOARules;
    
    for(let i=0; i<listRules.length; i++){
        strBody = listRules[i];
       
        a_classType = wordOut(strBody, "classtype:",";"); 
        b_sid = wordOut(strBody, "sid:",";"); 
        c_msg = wordOut(strBody, "msg:",";"); 
        
        if(( a_classType !=null)&(b_sid!=null)&(c_msg!=null)) {
               
            let check = c_msg.indexOf("\"");
            if(check != -1)
            {
                c_msg = c_msg.slice(c_msg.indexOf("\"")+1, c_msg.indexOf("\"", 3));
            }
            element = {
                sid: b_sid,
                classType: a_classType,
                msg: c_msg,
                body: strBody,
            };
            
            arrList.push(element);
            // console.log(`sid ${b_sid} classType ${a_classType}`);
        }
       
        
        //if(i>=15000) {break;}
        //if(i>=50) {break;}
        
    }
    //console.log(arrList);
    arrList.sort(function(x, y) { return x.sid - y.sid; });
    // arrList.sort((prev, next) => prev.sid - next.sid);
    return Promise.resolve(arrList);
}

/*
async function writeData(listRules){
    await ((listRules) => {
        return new Promise((resolve,reject) => {
            (require("../../middleware/mongodbQueryProcessor")).queryInsertMany(require("../../controllers/models").modelSOARules,  listRules, (err, doc) => {
                //if(err) reject(err);
                if(err) reject(err);
                else resolve(doc); 
            });
        });
    })(listRules);
}queryDataSave
*/
async function processing(fileName){
    // eslint-disable-next-line no-useless-catch
    try{
        let data = await readFileRule(fileName);
        let listRules = await parser(data);
        let mongooseModel = require("../../controllers/models").modelSOARules;
        let requireMong = (require("../../middleware/mongodbQueryProcessor"));
       
        await ((listRules ) => {
            return new Promise((resolve,reject) => {
                // requireMong.queryUpdate(mongooseModel,  listRules , (err, doc) => {
                requireMong.queryUpdateBD(mongooseModel,  listRules , (err, doc) => {
                    if(err) {
                        reject(err);
                    }
                    else resolve(doc); 
                });
            });
        })(listRules);

    } catch(err){
        throw err;
    }
}
/*
async function processing(fileName){
 
    // eslint-disable-next-line no-useless-catch
    try{
        let data = await readFileRule(fileName);
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

function receivedFilesRulesSOA(socketIo, stream, data){
    console.log("func 'receivedFilesRulesSOA', START...");
    console.log(data);

    // console.log(__dirname);
    // console.log(__dirname.substr(0, (__dirname.length - 28)));

    let filename = (__dirname.substr(0, (__dirname.length - 28)) + "uploads/") + path.basename(data.name);
    let tempFile = fs.createWriteStream(filename, { flags: "w", defaultEncoding: "utf8", autoClose: true });

    stream.pipe(tempFile);

    tempFile.on("close", () => {
        console.log("UPLOADING FILE IS COMPLETE");

        let fileName = (__dirname.substr(0, (__dirname.length - 28)) + "uploads/") + data.name;//"snort.rules"
        console.log(`Имя файла = ${fileName}`);
        
        processing(fileName).then(() => {
            console.log("ОK");

            socketIo.emit("file upload result", { info: "insert OK" });
        }).catch((err) => {
            //console.log(err);
            console.log(`--------> ${err}`);
            
            writeLogFile("error", `function 'receivedFilesRulesSOA': ${err.toString()}`);

            socketIo.emit("file upload result", { info: `insert ${err.toString()}` });
        });
    });
    
}