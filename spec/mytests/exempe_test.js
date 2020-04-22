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

describe("Тест 1. Читаю файл", () => {
    it("Должен быть выполнено чтение файла без ошибки", (done) => {

        fs.readFile(__dirname+"/example.js", "utf8", (err, data) => {

            expect(err).toBeNull();

            done();
        });
    });
});

describe("Тест 2. Читаю файл", () => {
    it("Должен быть выполнено чтение файла без ошибки", (done) => {

        fs.readFile(__dirname+"/example1.js", "utf8", (err, data) => {

            expect(true).toBeTrue();

            done();
        });
    });
});

describe("Тест 1. Запись в СУБД тестовых данных, без обработки объекта содержащего данные", () => {
    it("Должна быть создана иерархия организация -> подразделение -> источник ->, задача должна быть выполненна без ошибок", (done) => {
        async function createElements(){
            //Создание организации
            await (() => {
                return new Promise((resolve, reject) => {

                    console.log("CREATE NEW ORGANIZATION");

                    (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelOrganizationName, {
                        document: {
                            id: hexSumOrg,
                            date_register: +(new Date),
                            date_change: +(new Date),    
                            name: orgName,
                            legal_address: "123452 г. Москва, ул. Каланчевка, д. 89, ст. 1,",
                            field_activity: "космическая промышленность",
                            division_or_branch_list_id: [],
                        }
                    }, err => {
                        if (err) reject(err);
                        else resolve();
                    });
                });
            })().catch((err) => {
                throw err;
            });

            //Создание подразделения
            await (() => {
                return new Promise((resolve, reject) => {
                    (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelOrganizationName, {
                        query: { "id": hexSumOrg },
                        select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
                    }, (err, info) => {
                        if(err) reject(err);
                        else resolve(info);
                    });
                }).then((info) => {
                    if(info === null) return;

                    return new Promise((resolve, reject) => {

                        console.log("CREATE NEW DIVISION");

                        //Создаем запись о новом подразделении
                        (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelDivisionBranchName, {
                            document: {
                                id: hexSumDiv,
                                id_organization: hexSumOrg,
                                date_register: +(new Date),
                                date_change: +(new Date),    
                                name: divisionName,
                                physical_address: "г. Смоленск, ул. Зои партизанки, д. 45, к. 2",
                                description: "просто какое то описание",
                                source_list: [],
                            }
                        }, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    }).then(() => {
                        return new Promise((resolve, reject) => {
                            //Создаем связь между организацией и подразделением
                            (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelOrganizationName, {
                                query: { 
                                    "id": hexSumOrg, 
                                    "division_or_branch_list_id": { $ne: hexSumDiv },
                                },
                                update:{ $push: {"division_or_branch_list_id": hexSumDiv }},
                            }, (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                    });
                }).catch((err) => {
                    throw err;
                });
            })().catch((err) => {
                throw err;
            });

            //Создание первого источника
            await (() => {
                console.log("CREATE NEW SOURCE");

                //Создаем запись о новом источнике
                return new Promise((resolve, reject) => {
                    (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelDivisionBranchName, {
                        query: { "id": hexSumDiv },
                        select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
                    }, (err, info) => {
                        if(err) reject(err);
                        else resolve(info);
                    });
                }).then((info) => {
                    if(info === null) return;

                    return new Promise((resolve, reject) => {
                        //Создаем связь между организацией и подразделением
                        (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelDivisionBranchName, {
                            query: { 
                                "id": hexSumDiv, 
                                "source_list": { $ne: hexSumSource },
                            },
                            update:{ $push: {"source_list": hexSumSource }},
                        }, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    }).then(() => {
                        return new Promise((resolve, reject) => {
                            (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelSourcesParameter, {
                                document: {
                                    id: hexSumSource,
                                    id_division: hexSumDiv,
                                    source_id: sourceID,
                                    date_register: +(new Date),
                                    date_change: +(new Date),
                                    short_name: "Test Source",
                                    network_settings: { 
                                        ipaddress: "59.23.4.110", 
                                        port: 13113, 
                                        token_id: "ff24jgj8j328fn8n837ge7g2", 
                                    },
                                    source_settings: {
                                        type_architecture_client_server: "client",
                                        transmission_telemetry: false,
                                        maximum_number_simultaneous_filtering_processes: 5,
                                        type_channel_layer_protocol: "ip",
                                        list_directories_with_file_network_traffic: [
                                            "/test_folder_1",
                                            "/test_folder_2",
                                            "/test_folder_3",
                                        ],
                                    },
                                    description: "дополнительное описание для источника",
                                    information_about_app: {
                                        version: "0.11",
                                        date: "14.03.2020",
                                    },
                                }
                            }, (err) => {
                                if (err) reject(err);
                                else resolve();
                            }); 
                        });
                    });
                }).catch((err) => {
                    throw err;
                });
            })().catch((err) => {
                throw err;
            });

            //Создание второго источника
            await (() => {
                console.log("CREATE NEW SOURCE");
                
                return new Promise((resolve, reject) => {
                    (require("../../middleware/mongodbQueryProcessor")).querySelect(require("../../controllers/models").modelDivisionBranchName, {
                        query: { "id": hexSumDiv },
                        select: { _id: 0, __v: 0, date_register: 0, data_change: 0, },
                    }, (err, info) => {
                        if(err) reject(err);
                        else resolve(info);
                    });
                }).then((info) => {
                    if(info === null) return;

                    //Создаем запись о новом источнике
                    return new Promise((resolve, reject) => {
                        (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelSourcesParameter, {
                            document: {
                                id: hexSumSourceTwo,
                                id_division: hexSumDiv,
                                source_id: 1010,
                                date_register: +(new Date),
                                date_change: +(new Date),
                                short_name: "Test Source",
                                network_settings: { 
                                    ipaddress: "210.35.61.120", 
                                    port: 13113, 
                                    token_id: "fnue883fg8gf8g8ssf33f", 
                                },
                                source_settings: {
                                    type_architecture_client_server: "client",
                                    transmission_telemetry: false,
                                    maximum_number_simultaneous_filtering_processes: 5,
                                    type_channel_layer_protocol: "ip",
                                    list_directories_with_file_network_traffic: [
                                        "/test_new_folder_1",
                                        "/test_new_folder_2",
                                        "/test_new_folder_3",
                                    ],
                                },
                                description: "дополнительное описание для источника",
                                information_about_app: {
                                    version: "0.11",
                                    date: "14.03.2020",
                                },
                            }
                        }, (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                    }).then(() => {
                        return new Promise((resolve, reject) => {
                        //Создаем связь между организацией и подразделением
                            (require("../../middleware/mongodbQueryProcessor")).queryUpdate(require("../../controllers/models").modelDivisionBranchName, {
                                query: { 
                                    "id": hexSumDiv, 
                                    "source_list": { $ne: hexSumSourceTwo },
                                },
                                update:{ $push: {"source_list": hexSumSourceTwo }},
                            }, (err) => {
                                if (err) reject(err);
                                else resolve();
                            });
                        });
                    });
                }).catch((err) => {
                    throw err;
                });
            })().catch((err) => {
                throw err;
            });
        }    

        createElements()
            .then(() => {
                done();
            }).catch((err) => {
                expect(err).toBeNull();

                done();
            });
    });
});

/*
describe("Тест 2. ШШШШшш", () => {
    it("Должен быть получено FALSE, так как такой ОРГАНИЗАЦИ нет в БД", () => {
        expect("idgi").toBeNull();
    
    });
});
*/