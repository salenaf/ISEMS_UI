const fs = require("fs");

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

                callback(null, count, listFilterProcess);
            }).catch((err) => {
                callback(err);
            });
        }

        testProcessFiltering("/home/development/modul_api_interaction/information_response_1589542887119.txt", (err, countString, list) => {

            console.log(`count string process filter = ${countString}`);
            console.log(list);

            /*socketIo.emit("module NI API", { 
                                "type": "filtrationProcessing",
                                "options": {
                                    sourceID: item.options.id,
                                    name: "пока тестовое имя источника",
                                    taskID: item.taskID,
                                    taskIDModuleNI: item.options.tidapp,
                                    status: item.options.s,
                                    parameters: {
                                        numAllFiles: item.options.nfmfp,
                                        numProcessedFiles: item.options.npf,
                                        numFindFiles: item.options.nffrf,
                                        sizeAllFiles: item.options.sfmfp,
                                        sizeFindFiles: item.options.sffrf,
                                    },
                                },
                            });*/

            /**
                Это функция для тестирования, но нужно как то читать 
                массив с задержкой хотя бы в секунду
            */

            expect(err).toBeNull();
            expect(countString).toEqual(33);

            done();
        });
    });
});