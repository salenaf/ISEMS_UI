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
    let userLogin = "jasmine111";
    let hexSum = (require("../../libs/helpers/createUniqID")).getMD5(`user_name_${userLogin}`);

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

            expect(err).toBeNull();
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

    /*it("Должен вернутся список из 4-ох пользователей", function(done) {
        (require("../../libs/management_settings/informationForPageManagementUsers"))((err, list) => {

            expect(err).toBeNull();
            expect(list.length).toEqual(4);

            done();
        });
    });*/

    it("Должен быть успешно добавлен один пользователь. Список из пользователей будет равен 5.", function(done) {
        new Promise((resolve, reject) => {

            console.log("Add user");


            (require("../../middleware/mongodbQueryProcessor")).queryCreate(require("../../controllers/models").modelUser, {
                document: {
                    user_id: hexSum,
                    date_register: +(new Date()),
                    date_change: +(new Date()),
                    login: userLogin,
                    password: "ixiw92f",
                    group: "administrator",
                    user_name: "Пользователь Жасмин",
                    settings: {
                        sourceMainPage: []
                    }
                }
            }, err => {
                if (err) reject(err);
                else resolve();
            });
        }).then(() => {
            return new Promise((resolve, reject) => {

                console.log("Get count users");

                (require("../../libs/management_settings/informationForPageManagementUsers"))((err, newUserList) => {
                    if (err) reject(err);
                    else resolve(newUserList.length);
                });
            });
        }).then(num => {

            console.log(`Count users is '${num}'`);

            expect(num).toEqual(5);

            done();
        }).catch(err => {
            expect(err).toBeNull();

            done();
        });
    });

    it(`Пользователь с ID ${hexSum} должен быть успешно удален`, function(done) {
        new Promise((resolve, reject) => {
            (require("../../middleware/mongodbQueryProcessor")).queryDelete(require("../../controllers/models").modelUser, { query: { user_id: hexSum } }, (err, user) => {
                if (err) reject(err);
                else resolve(user);
            });
        }).then(user => {

            console.log(user);

            done();
        }).catch(err => {
            expect(err).toBeNull();

            done();
        });
    });
});