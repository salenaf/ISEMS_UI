"use strict";

/**
 * функция генерирует различные сообщения от пользователя
 */
function exampleUserMessage(){
    console.log("\x1b[32m%s\x1b[0m", "func 'exampleUserMessage', START...\n");

    const EventEmitter = require("events").EventEmitter;
    class MyEventEmitter extends EventEmitter {
        constructor(){
            super();
        }
    }

    const myEventEmitter = new MyEventEmitter();

    /*
    Examlpe object:

        "Описание организации": {
            name: "", // название организации (String) а-Я0-9"'.,()-
            legal_address: "", // юридический адрес (String) а-Я0-9.,
            field_activity: "", // род деятельности (String) из заданных значений или значение по умолчанию
            division_or_branch_list_id: [] // массив с объектами типа addDivision
        }

        "Описание филиала или подразделения организации": {
            id_organization: "", // уникальный идентификатор организации (String) a-Z0-9
            name: "", // название филиала или подразделения организации (String) а-Я0-9"'.,()-
            physical_address: "", // физический адрес (String) а-Я0-9.,
            description: "", // дополнительное описание (String) а-Я0-9"'.()-
            source_list: [], // массив с объектами типа addSource
        }

        "Описание источника обработки файлов, установленного в филиала или подразделения организации": {
            id_division: "", // уникальный идентификатор филиала или подразделения организации (String) a-Z0-9
            source_id: "", // уникальный идентификатор источника (Number) 0-9
            short_name: "", // краткое название источника (String) a-Z-_0-9
            network_settings: { // сетевые настройки для доступа к источнику
                ipaddress: "", // ip адрес (String) Проверка ip адреса на корректность
                port: 0, // сетевой порт (Number) 0-9 и диапазон 1024-65565
                token_id: "", // идентификационный токен (String) a-Z0-9
            },
            source_settings: { // настройки источника 
                type_architecture_client_server: "", // тип клиент серверной архитектуры (источник работает в режиме клиент или сервер) (String) a-z
                transmission_telemetry: false, // отправка телеметрии (Bool) BOOL
                maximum_number_simultaneous_filtering_processes: 0, // максимальное количество одновременных процессов фильтрации (Number) 0-9 и диапазон 1-10
                type_channel_layer_protocol: "", // тип протокола канального уровня (String) tcp/udp/any
                list_directories_with_file_network_traffic: [], // список директорий с файлами сетевого трафика, длинна массива не должна быть 0, массив
                 содержит сторки с символами /\_a-Z0-9
            },
            description: "", // дополнительное описание (String) а-Я0-9"'.,()-
        }
    */

    const exampleList = [
        {
            testDescription: "Добавляем организацию. Validation: success.",
            testObject: {
                name: "ПАО 'Научно исследовательский и конструкторский институт энергетики имени Н.А. Доллежаля'",
                legal_address: "234109 г. Москва, Варшавское шоссе, д. 38 к.2",
                field_activity: "атомная промышленность",
                division_or_branch_list_id: [],
            },
        },
        {            
            testDescription: "Добавляем организацию. Validation: success.",
            testObject: {
                name: "Территориальный орган федеральной службы государственной статистики по Воронежской области",
                legal_address: "4129 г. Брянск, ул. 50-ти летия октября, д. 11",
                field_activity: "государственный орган",
                division_or_branch_list_id: [],
            },
        },
        {            
            testDescription: "Добавляем организацию. Validation: unsuccessful.",
            testObject: {
                name: "АО \"АВИААВТОМАТИКА\" им. В.В, @ Тарасова",
                legal_address: "743843 г. Москва, ул. Соколиная гора, д.18",
                field_activity: "военно-промышленный комплекс",
                division_or_branch_list_id: [],
            },
        },
        {            
            testDescription: "Добавляем организацию, филиала или подразделения организации и настройки источника. Validation: success.",
            testObject: {
                name: "Государственная корпорация по космической деятельности \"РОСКОСМОС\"",
                legal_address: "234891 г. Москва, Дмитровское шоссе, д.168, к. 56",
                field_activity: "космическая промышленность",
                division_or_branch_list_id: [
                    {
                        id_organization: "",
                        name: "Центр обработки данных (ЦОД) - 1",
                        physical_address: "г. Москва, ул. Большая Черкизовская, д. 78, ст. 4",
                        description: "Первый ЦОД",
                        source_list: [],
                    },
                    {
                        id_organization: "",
                        name: "Центр обработки данных (ЦОД) - 2",
                        physical_address: "г. Обнинск, ул. Петроградская, д. 51",
                        description: "Второй ЦОД",
                        source_list: [
                            {
                                id_division: "",
                                source_id: 1000,
                                short_name: "Rosskosmos COD-1",
                                network_settings: { 
                                    ipaddress: "96.123.0.36",
                                    port: 13113,
                                    token_id: "tfeis99nff898449hhgdf",
                                },
                                source_settings: { 
                                    type_architecture_client_server: "client",
                                    transmission_telemetry: false,
                                    maximum_number_simultaneous_filtering_processes: 0,
                                    type_channel_layer_protocol: "",
                                    list_directories_with_file_network_traffic: [
                                        "/__CURRENT_DISK_1",
                                        "/__CURRENT_DISK_2",
                                        "/__CURRENT_DISK_3",
                                    ],
                                },
                                description: "какое то дополнительное описание",
                            },
                            {
                                id_division: "",
                                source_id: 1001,
                                short_name: "Rosskosmos COD-2",
                                network_settings: { 
                                    ipaddress: "69.123.50.3",
                                    port: 13113,
                                    token_id: "nif0303u99th49h44fe",
                                },
                                source_settings: { 
                                    type_architecture_client_server: "client",
                                    transmission_telemetry: false,
                                    maximum_number_simultaneous_filtering_processes: 5,
                                    type_channel_layer_protocol: "",
                                    list_directories_with_file_network_traffic: [
                                        "/source_folder_1",
                                        "/source_folder_2",
                                        "/source_folder_3",
                                    ],
                                },
                                description: "",
                            },
                        ],
                    },
                ],
            },
        },
        {            
            testDescription: "Добавляем филиал или подразделение организации. Validation: success.",
            testObject: {
                id_organization: "nfi38993fh48hg85855",
                name: "ОБУ \"Информационный-технический центр\"",
                physical_address: "г. Щелково, ул. Ленина, д. 5, ст. 1",
                description: "",
                source_list: [],
            },
        },
        {            
            testDescription: "Добавляем филиал или подразделение организации. Validation: unsuccessful.",
            testObject: {
                id_organization: "",
                name: "Цех №2 смоленского авиационного завода",
                physical_address: "г. Смоленск, ул. Тараса Шевченко, д. 7, к. 2",
                description: "",
                source_list: [],
            },
        },
        {            
            testDescription: "Добавляем филиал или подразделение организации и настройки источника. Validation: success.",
            testObject: {
                id_organization: "fnf38fg838rtg737fg23",
                name: "Управление ФСБ России По Тверской области",
                physical_address: "г. Тверь, ул. Остапа, д. 15",
                description: "тверской филиал",
                source_list: [
                    {
                        id_division: "",
                        source_id: 1020,
                        short_name: "UFSB Tver user segment",
                        network_settings: { 
                            ipaddress: "77.230.66.9",
                            port: 13113,
                            token_id: "hd8288g38g47g47gf489f84tr",
                        },
                        source_settings: { 
                            type_architecture_client_server: "client",
                            maximum_number_simultaneous_filtering_processes: 5,
                            type_channel_layer_protocol: "",
                            list_directories_with_file_network_traffic: [
                                "/source_folder_1",
                                "/source_folder_2",
                                "/source_folder_3",
                            ],
                        },
                        description: "",
                    },
                    {
                        id_division: "",
                        source_id: 1021,
                        short_name: "UFSB Tver COD",
                        network_settings: { 
                            ipaddress: "77.230.66.91",
                            port: 13113,
                            token_id: "nf9h39hf93h743824rf",
                        },
                        source_settings: { 
                            type_architecture_client_server: "client",
                            transmission_telemetry: false,
                            maximum_number_simultaneous_filtering_processes: 5,
                            type_channel_layer_protocol: "",
                            list_directories_with_file_network_traffic: [
                                "/current_folder_1",
                                "/current_folder_2",
                                "/current_folder_3",
                            ],
                        },
                        description: "",
                    },
                ],
            },
        },
        {
            testDescription: "Добавляем настройки источника. Validation: success.",
            testObject: {
                id_division: "f939f399y384y838ty48t",
                source_id: 1030,
                short_name: "UFSB Orel",
                network_settings: { 
                    ipaddress: "56.6.10.36",
                    port: 13113,
                    token_id: "foefoeof309998h349htr84",
                },
                source_settings: { 
                    type_architecture_client_server: "",
                    transmission_telemetry: false,
                    maximum_number_simultaneous_filtering_processes: 3,
                    type_channel_layer_protocol: "",
                    list_directories_with_file_network_traffic: [
                        "/current_folder_1",
                        "/current_folder_2",
                        "/current_folder_3",
                    ],
                },
                description: "",
            },
        },
        {
            testDescription: "Добавляем настройки источника. Validation: unsuccessful.",
            testObject: {
                id_division: "f939f399y384y838ty48t",
                source_id: 1035,
                short_name: "UFSB Riazan",
                network_settings: { 
                    ipaddress: "569.144.6.46",
                    port: 13113,
                    token_id: "",
                },
                source_settings: { 
                    type_architecture_client_server: "",
                    transmission_telemetry: false,
                    maximum_number_simultaneous_filtering_processes: 3,
                    type_channel_layer_protocol: "",
                    list_directories_with_file_network_traffic: [
                        "/current_folder_1",
                        "/current_folder_2",
                        "/current_folder_3",
                    ],
                },
                description: "",
            },
        },
        {            
            testDescription: "--- Test END ---",
            testObject: {},
        },
    ];

    let num = 0;
    let timer = setInterval(() => {
        if(num === exampleList.length){
            clearTimeout(timer);

            return;
        }


        myEventEmitter.emit("user message", JSON.stringify({
            numberMessage: num,
            descriptionMessage: exampleList[num].testDescription,
            testMessage: exampleList[num].testObject,
        }));

        num++;
    }, 3000);

    return myEventEmitter;
}

(exampleUserMessage()).on("user message", (message) => {
    console.log(`received a message from the user: ${message}\n`);
}).on("error", (err) => {
    console.log("received error");
    console.log(err);
});

/**
 * Функция декодирующая JSON строку в JavaScript объект
 * 
 * @param {*} stringJSON - строка в формате JSON
 * @param {*} callback - функция обратного вызова с сигнатурой callback(error, objectJSON) 
 */
function parseJSON(stringJSON, callback){
/** код... */

    return callback(new Error("ошибка парсинга JSON строки"), {});
}

/**
 * Функция проверяющая переданные пользователем параметры
 * 
 * Функция принимает объект, верифицирует его свойства и возвращает валидный объект,
 * при этом некоторые параметры могут заменятся значениями по умолчанию если данного параметра нет,
 * оно не определено или выходит за рамки допустимых значений.
 * Например:
 *  field_activity - род деятельности (default value = "иная деятельность")
 *  type_architecture_client_server - server/client (default value = "client")
 *  transmission_telemetry - true/false (default value = "false")
 *  maximum_number_simultaneous_filtering_processes - от 1 до 10 (default value = 3)
 *  type_channel_layer_protocol - tcp/udp/any (default value = any)
 * 
 * Объект однозначно признается невалидным если некорректны или не заполненные следующие параметры:
 *  - list_directories_with_file_network_traffic
 *  - token_id
 *  - ipaddress
 *  - port
 * 
 * Проверка полей id_division и id_organization не выполняется а их значения не учитываются если объект
 * содержащий эти поля является дочерним родительского объекта
 * 
 * @param {*} IncomingObject - входящий объект
 * @param {*} callback - функция обратного вызова
 */
function checkingIncomingParameters(IncomingObject, callback){
    let validObject = {};
    let err = new Error("error message");
    const listFieldActivity = [
        "атомная промышленность",
        "военно-промышленный комплекс",
        "образовательные учреждения",
        "органы безопасности",
        "государственные органы",
        "космическая промышленность"    
    ];

    /** код... */

    return callback(err, validObject);
}