"use strict";

const fs = require("fs");
const path = require("path");

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
        ss(socketIo).on(e, handlers[e].bind(null));
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
    let possition = 0;
    let arrList = [];
    let element ;
    let n = Number(data.length);
    console.log(`${n}`); 
    let i =0, a,b,c;
    let strBody = "", strBody1 = "";
    //for(let i = 0; i<5; i++){

    while (data.indexOf("alert", possition)!=-1){
        strBody = wordOut(data, "alert ", ")", possition);
        strBody = "alert "+ strBody + ")";

        if(strBody != strBody1){
            a = wordOut(strBody, "classtype:",";"); 
            b = wordOut(strBody, "sid:",";"); 
            c = wordOut(strBody, "msg:",";"); 
            //if(b!= arrList[i-1].sid){        }
            if((a!=null)&(b!=null)&(c!=null)) {
           
                element = {
                    sid: b,
                    classType: a,
                    msg: c,
                    body: strBody,
                //possition: possition,
                };
                arrList.push(element);
                console.log(`sid = ${b}, classType: ${a}, msg: ${c}, possition = ${possition}`);
                //console.log (`resultStr = ${strBody}`); 
                i++;
            }
        }
        if(possition == 72067) console.log(`body = ${strBody}`);
        if(possition == 72182) console.log(`body = ${strBody}`);
        strBody1 = strBody;
        possition = data.indexOf(")", possition);
        possition = data.indexOf("alert", possition);
            
        if(i>=15000) {break;}
    }



    return Promise.resolve(arrList);
}

async function processing(fileName){
    try{
        let data = await readFileRule(fileName);
        let listRules = await parser(data);
        await ((listRules) => {
            return new Promise((resolve,reject) => {
                (require("../../middleware/mongodbQueryProcessor")).queryInsertMany(require("../../controllers/models").modelSOARules, listRules, (err, doc) => {
                //if(err) reject(err);
                    if(err) reject(err);
                    else resolve(doc); 
                });
            });
        })(listRules);
        //callBack(null);
    } catch(err){
        // callBack(err);
        throw err;
    }

}

function receivedFilesRulesSOA(stream, data){
    console.log("func 'receivedFilesRulesSOA', START...");
    console.log(data);

    console.log(__dirname);
    console.log(__dirname.substr(0, (__dirname.length - 28)));

    let filename = (__dirname.substr(0, (__dirname.length - 28)) + "uploads/") + path.basename(data.name);
    let tempFile = fs.createWriteStream(filename, { flags: "w", defaultEncoding: "utf8", autoClose: true });

    stream.pipe(tempFile);

    tempFile.on("close", () => {
        console.log("UPLOADING FILE IS COMPLETE");

        let fileName = (__dirname.substr(0, (__dirname.length - 28)) + "uploads/") + "snort.rules";
        console.log(`Имя файла = ${fileName}`);
        processing(fileName).then(() => {
            console.log("ОK");
        }).catch((err) => {
            console.log(err);
        });


    });

}