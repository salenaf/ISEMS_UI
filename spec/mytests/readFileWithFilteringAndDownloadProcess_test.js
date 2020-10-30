const fs = require("fs");
const EventEmitter = require("events");

class MyEmitter extends EventEmitter {}

describe("Тест 1. Читаем файл с информацией о процессе фильтрации файлов и формируем JSON объект", () => {
    it("Файл должен быть успешно прочитан и на каждую строку сформирован JSON объект", (done) => {
        function testProcessFiltering(filePath, callback) {
            console.log(filePath);

            new Promise((resolve, reject) => {
                fs.readFile(filePath, "utf8", (err, data) => {
                    if(err){
                        reject(err);
                    }

                    resolve(data);
                });
            }).then((data) => {
                let stringList = data.split("\n");

                console.log(stringList.length);

                let count = 0;
                let listFilterProcess = [];
                stringList.forEach((item) => {
                    if(item.length > 0){
                        let objTmp = JSON.parse(item);
    
                        //только для процесса фильтрации
                        if(objTmp.instruction === "task processing" && (typeof objTmp.options.ffi !== "undefined")){
                            count++;
                            listFilterProcess.push(item);
                        }
                    }
                });

                //console.log(data);

                return { count: count, list: listFilterProcess };
            }).then((obj) => {
                const myEmitter = new MyEmitter();

                let numInterval = 0;
                let timerID = setInterval(() => {
                    if(numInterval === obj.count){
                        clearInterval(timerID);

                        myEmitter.emit("finish", {});
                    }

                    console.log(`received next emit, num: ${numInterval}`);
                    //console.log(obj.list[numInterval]);

                    let objTmp = JSON.parse(obj.list[numInterval]);
                    myEmitter.emit("next emit", { 
                        "type": "filtrationProcessing",
                        "options": {
                            sourceID: objTmp.options.id,
                            name: "shortName",
                            taskID: objTmp.taskID,
                            taskIDModuleNI: objTmp.options.tidapp,
                            status: objTmp.options.s,
                            parameters: {
                                numDirectoryFiltration: objTmp.options.ndf,
                                numAllFiles: objTmp.options.nfmfp,
                                numProcessedFiles: objTmp.options.npf,
                                numProcessedFilesError: objTmp.options.nepf,
                                numFindFiles: objTmp.options.nffrf,
                                sizeAllFiles: objTmp.options.sfmfp,
                                sizeFindFiles: objTmp.options.sffrf,
                            },
                        }});                    

                    numInterval++;
                },1000);

                callback(null, { 
                    count: obj.count, 
                    list: obj.list,
                    myEmitter: myEmitter,
                });
            }).catch((err) => {
                callback(err);
            });
        }

        testProcessFiltering("/home/development/modul_api_interaction/information_response_1589542887119.txt", (err, obj) => {

            //console.log(`count string process filter = ${obj.count}`);
            //console.log(obj.list);

            obj.myEmitter.on("next emit", (data) => {

                console.log(data);

            }).on("finish", () => {
                console.log(`received event 'finish' (${new Date})`);

                done();
            });

            expect(err).toBeNull();
            expect(obj.count).toEqual(33);
        });
    });
});