const fs = require("fs");

const config = require("../../configure");

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

function  wordOut(strBody, keywordStart, keywordEnd, posNull =0 ){
    // let strBody ="alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (  msg:\"Downloader.MediaDrug.HTTP.C&C\"; flow:established,to_server;  content:\"GET\"; http_method; content:\"advert_key=\"; http_uri; fast_pattern;   content:\"app=\"; http_uri;  content:\"oslang=\"; http_uri; classtype:trojan-activity; sid:35586741; rev:0;)";
    /*
    let keyword1= "classtype";
    let keywordEnd1 = ";";              */

    let posStart = 0, posEnd = 0;
    posStart = strBody.indexOf(keywordStart , posNull);
    posEnd = strBody.indexOf(keywordEnd, posStart+1);
    let resultStr = strBody.slice(posStart + keywordStart.length + 1 , posEnd) ;
    // console.log (`pos1 = ${posStart}; pos2 = ${posEnd}; resultStr = ${resultStr}`);
    
    return resultStr;
}
/**
 (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelDivisionBranchName, {            
    query: { "name": entity.id_division },
                select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
            }, (err, info) => {
                if(err) reject(err);
                else resolve(info);
            });
 
 (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelSOARules, {            
{ document: {} }
                select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
            }, (err, info) => {
                if(err) reject(err);
                else resolve(info);
            });

            */
describe("Тест 1. Читаю файл", () => {
    it("Должен быть выполнено чтение файла без ошибки", (done) => {
        let filename = (__dirname.substr(0, (__dirname.length-12)) + "/uploads/") + "snort.rules";
        
        fs.readFile(filename, "utf8", (err, data) => {
            
            //console.log(data);
            // let strBody1 ="alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (  msg:\"Downloader.MediaDrug.HTTP.C&C\"; flow:established,to_server;content:\"GET\"; http_method; content:\"advert_key=\"; http_uri; fast_pattern; content:\"app=\"; http_uri;  content:\"oslang=\"; http_uri; classtype:trojan-activity; sid:35586741; rev:0;)";
            let possition = 0;
            let arrList = [];
            let element ;
            let n = Number(data.length);
            console.log(`${n}`);
            //for(let i = 0; i<5; i++){
            while (data.indexOf("alert", possition+1)!=-1){
                let strBody = wordOut(data, "alert", ")", possition+1);
                strBody = "alert "+ strBody + ")";

                let a = wordOut(strBody, "classtype",";"); 
                let b = wordOut(strBody, "sid",";"); 
                let c = wordOut(strBody, "msg",";"); 
                
                element = {
                    sid: b,
                    classType: a,
                    msg: c,
                    body: strBody,
                    //possition: possition,
                };
                arrList.push(element);
                possition = data.indexOf(")", possition+1);
            }
            console.log(`n = ${arrList.length}`);
            //console.log(`0.pos = \"${arrList[43712].possition}\"`);
            console.log(`1. str = \"${arrList[43712].body}\"`);
            console.log(`2. classType = ${arrList[43712].classType}, sid = ${arrList[43712].sid}, msg = ${arrList[43712].msg}`);
            /*
            123: {
                "classType": "trojan-activity",
                "body": "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (  msg:\"Downloader.MediaDrug.HTTP.C&C\"; flow:established,to_server;  content:\"GET\"; http_method; content:\"advert_key=\"; http_uri; fast_pattern;   content:\"app=\"; http_uri;  content:\"oslang=\"; http_uri; classtype:trojan-activity; sid:35586741; rev:0;)"
            },*/
            
            /*  require("../../controllers/models").modelSOARules.InsertMany(arrList, (err) => {
                if(err) console.log(`ERROR: ${err.toString()}`);

                expect(err).toBeNull();
                done(); 
            });*/
            (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelSOARules, {            
                document: arrList[2]
            }, (err) => {
                //if(err) reject(err);
                if(err) console.log(`ERROR: ${err.toString()}`);

                expect(err).toBeNull();
                done(); 
            });
        });
    });
});
/*
describe("Тест 2. Читаю файл", () => {
    it("Должен быть выполнено чтение файла без ошибки", (done) => {

        fs.readFile(__dirname+"/example.js", "utf8", (err, data) => {

            expect(true).toBeTrue();

            done();
        });
    });
});



describe("Тест 2. ШШШШшш", () => {
    it("Должен быть получено FALSE, так как такой ОРГАНИЗАЦИ нет в БД", () => {
        expect("idgi").toBeNull();
    
    });
});
*/