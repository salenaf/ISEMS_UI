const config = require("../../configure");

const helpersFunc = require("../../libs/helpers/helpersFunc");
const globalObject = require("../../configure/globalObject");
const connectMongoDB = require("../../controllers/connectMongoDB");

describe("Тест 1. Проверка функции для тестирования переданных пользователем данных", function() {
    it("На валидные данные должно быть TRUE", function() {
        let isValide = helpersFunc.checkUserSettingsManagementUsers({
            user_name: "Третий Чает ввы",
            work_group: "administrator",
            user_login: "testuser_3",
            user_password: "1234qwer",
        });
        expect(isValide).toBe(true);
    });
});

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

describe("Тест 2. Проверка функций взаимодействующих с СУБД", function() {
    it("Запрос пользователя по логину (ПОЛЬЗОВАТЕЛь НАЙДЕН)", function(done) {
        (require("../../libs/management_settings/informationAboutUser"))("administrator", (err, userInfo) => {
            //console.log(userInfo);

            expect(userInfo.user_name).toEqual("Администратор");
            expect(err).toBeNull();

            done();
        });

    });

    it("Запрос пользователя по логину (ПОЛЬЗОВАТЕЛь НЕ НАЙДЕН)", function(done) {
        (require("../../libs/management_settings/informationAboutUser"))("fssdfrator", (err, userInfo) => {
            console.log(err);

            expect(userInfo).toBeNull();

            done();
        });

    });

    it("Список групп пользователей", function(done) {
        (require("../../libs/management_settings/informationItemGroups"))((err, list) => {
            //console.log(list);
            //console.log(Array.isArray(list));

            let loginAdd = "administrator";

            let isExist = list.some(elem => {
                return elem === loginAdd;
            });

            expect(err).toBeNull();
            expect(isExist).toBe(true);

            done();
        });
    });
});

/*it("Запрос информации к СУБД", function(done) {
        connectMongoDB()
            .then(description => {
                return new Promise((resolve, reject) => {
                    process.nextTick(() => {
                        globalObject.setData("descriptionDB", "MongoDB", {
                            "connection": description,
                            "connectionTimestamp": +new Date(),
                            "userName": config.get("mongoDB:user")
                        });

                        let connectDB = globalObject.getData("descriptionDB", "MongoDB", "connection");

                        console.log(connectDB);

                        if (connectDB === null) reject(new Error("the database connection is not established"));
                        else resolve(null);
                    });
                });
            }).then(() => {
                return new Promise((resolve, reject) => {
                    require("../../controllers/createSchemasMongoDB")(err => {
                        if (err) reject(err);
                        else resolve(null);
                    });
                });
            }).then(() => {
                (require("../../libs/management_settings/informationAboutUser"))("aadministrator", (err, userInfo) => {
                    if (err) console.log(err);

                    console.log(userInfo);

                    expect(userInfo.user_name).toEqual("Администратор");
                    expect(err).toBeNull();

                    let connectDB = globalObject.getData("descriptionDB", "MongoDB", "connection");
                    connectDB.close();

                    done();
                });
            }).catch(err => {
                expect(err).toBeNull();

                let connectDB = globalObject.getData("descriptionDB", "MongoDB", "connection");
                connectDB.close();

                done();
            });
    });*/