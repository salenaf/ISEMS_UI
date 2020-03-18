"use strict";

/**
 * функция генерирует различные сообщения от пользователя
 */

  /**
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
//name="",legal_address="", field_activity= "иная деятельность"
class addOrganization {  
    name                       = "";                                        // название организации (String) а-Я0-9"'.,()-
    legal_address              = "";                                        // юридический адрес (String) а-Я0-9.,
    field_activity             = "";                                        // род деятельности (String) из заданных значений или значение по умолчанию
    division_or_branch_list_id = [];                                        // массив с объектами типа addDivision
    error = false;

    constructor(testObject, i) {
        this.name           = "" + testObject.name;                                          
        this.legal_address  = "" + testObject.legal_address;                                       
        this.field_activity = "" + testObject.field_activity; 
        this.error = this.check(i);

        if(typeof testObject.division_or_branch_list_id == 'object' ){
            for (let j=0;  j < testObject.division_or_branch_list_id.length; j++)
            {  
                let testDivision = new addDivision(testObject.division_or_branch_list_id[j], i);
                if(testDivision.error){
                    this.error = testDivision.error;
                }
                this.division_or_branch_list_id += testDivision;
            } 
        }
    };

    check (i) {
        let error = false;
        
        let regName =  new RegExp(/[^\p{L}\p{N}\s"'.,()-]/gui);                 //  а-Я0-9"' .,()-
        let checkName =  this.name.match(regName);      
        if(checkName!=null){
            console.log(`В сообщении № ${i} addOrganization.name содержит недопустимый(е) символ(ы): ${checkName}`);    
            error = true; this.name = "";
        } 

        let regAddress =  new RegExp(/[^\p{L}\p{N}\s.,-]/gui);                  // а-Я 0-9.,-
        let checkAddress =  this.legal_address.match(regAddress);      
        if(checkAddress!=null){
            console.log(`В сообщении № ${i} addOrganization.legal_address содержит недопустимый(е) символ(ы): ${checkAddress}`); 
            error = true; this.legal_address = "";       
        }
        const listFieldActivity = [
            "иная деятельность" ,
            "атомная промышленность",
            "военно-промышленный комплекс",
            "образовательные учреждения",
            "органы безопасности",
            "государственные органы",
            //"государственный орган",
            "космическая промышленность"
               // !!!!!!!!
        ];
        let checked = false;
        for (let k=0; k < 7; k++ ){
            if(this.field_activity==listFieldActivity[k]){
                checked = true;
            }
        }

        if (checked == false){
            this.field_activity=listFieldActivity[0];
            console.log(`В сообщении № ${i} addOrganization.field_activity замещено поумолчанию`);
        }
        return error;
    };
  }
   
  class addDivision {                                               //"Описание филиала или подразделения организации": {
    id_organization = "";                                           // уникальный идентификатор организации (String) a-Z0-9
    name = "";                                                      // название филиала или подразделения организации (String) а-Я0-9"'.,()-
    physical_address = "";                                          // физический адрес (String) а-Я0-9.,
    description = "";                                               // дополнительное описание (String) а-Я0-9"'.()-
    source_list = [];                                               // массив с объектами типа addSource
    error = false;

     constructor(testObjectDivis,i) {
        this.name             = "" + testObjectDivis.name;                                          //.division_or_branch_list_id
        this.id_organization  = "" + testObjectDivis.id_organization;                             
        this.physical_address = "" + testObjectDivis.physical_address;    
        this.description      = "" + testObjectDivis.description; 
        this.error = this.check (i);
        
        for (let j = 0; j < testObjectDivis.source_list.length;  j++)
        {  
            let testSource = new addSource(testObjectDivis.source_list[j],i);
            if(testSource.error){
                this.error = testSource.error;
            }
            this.source_list += testSource;
        }    
    };
    
    check (i) {
        let error = false;

        let regIdOrganization =  new RegExp(/[^a-zA-Z\p{N}]/gui);                  // a-Z0-9
        let checkIdOrganization =  this.id_organization.match(regIdOrganization);      
        if(checkIdOrganization!=null){
            console.log(`В сообщении № ${i} addDivision.id_organization содержит недопустимые символы: ${checkAddress}`); 
            error = true;        
        }

        let regName =  new RegExp(/[^\p{L}\p{N}\s"'.,()-]/gui);                 //  а-Я0-9"' .,()-
        let checkName =  this.name.match(regName);      
        if(checkName!=null){
            console.log(`В сообщении № ${i} addDivision.name есть недопустимые символы: ${checkName}`);    
            error = true; 
        }

        let regAddress =  new RegExp(/[^\p{L}\p{N}\s.,-]/gui);                  // а-Я 0-9.,-
        let checkAddress =  this.physical_address.match(regAddress);      
        if(checkAddress!=null){
            console.log(`В сообщении № ${i} addDivision.physical_address есть недопустимые символы: ${checkAddress}`); 
            error = true;        
        }

        let regDescrip =  new RegExp(/[^\p{L}\p{N}\s"'.,()-]/gui);                 //  а-Я0-9"' .,()-
        let checkDescrip =  this.description.match(regDescrip);      
        if(checkDescrip!=null){
            console.log(`В сообщении № ${i} addDivision.description есть недопустимые символы: ${checkDescrip}`);    
            error = true; 
        }
        return error;
    };
}

// "Описание источника обработки файлов, установленного в филиала или подразделения организации": 
class addSource  {
    error = false;
    id_division = "";                                           // уникальный идентификатор филиала или подразделения организации (String) a-Z0-9
    source_id = "";                                             // уникальный идентификатор источника (Number) 0-9
    short_name = "";                                            // краткое название источника (String) a-Z-_0-9

    network_settings = {                                        // сетевые настройки для доступа к источнику
        ipaddress: "",                                          // ip адрес (String) Проверка ip адреса на корректность
        port: 0,                                                // сетевой порт (Number) 0-9 и диапазон 1024-65565
        token_id: "",                                           // идентификационный токен (String) a-Z0-9
    };
    source_settings = {                                         // настройки источника 
        type_architecture_client_server: "",                    // тип клиент серверной архитектуры (источник работает в режиме клиент или сервер) (String) a-z
        transmission_telemetry: false,                          // отправка телеметрии (Bool) BOOL
        maximum_number_simultaneous_filtering_processes: 0,     // максимальное количество одновременных процессов фильтрации (Number) 0-9 и диапазон 1-10
        type_channel_layer_protocol: "",                        // тип протокола канального уровня (String) tcp/udp/any
        list_directories_with_file_network_traffic: [],         // список директорий с файлами сетевого трафика, длинна массива не должна быть 0, массив
                                                                //содержит сторки с символами /\_a-Z0-9
    };
    description = "";                                           // дополнительное описание (String) а-Я0-9"'.,()-

    constructor(testObjecSource, i){
        this.id_division = "" + testObjecSource.id_division; 
        this.source_id   = "" + testObjecSource.source_id; 
        this.short_name  = "" + testObjecSource.short_name; 
    
        this.network_settings = { 
            ipaddress: testObjecSource.network_settings.ipaddress, 
            port     : testObjecSource.network_settings.port,
            token_id : testObjecSource.network_settings.token_id, 
        };

        this.source_settings = {                                
            type_architecture_client_server                 : testObjecSource.source_settings.type_architecture_client_server,                
            transmission_telemetry                          : testObjecSource.source_settings.transmission_telemetry,                      
            maximum_number_simultaneous_filtering_processes : testObjecSource.source_settings.maximum_number_simultaneous_filtering_processes, 
            type_channel_layer_protocol                     : testObjecSource.source_settings.type_channel_layer_protocol,                    
            list_directories_with_file_network_traffic      : [],    
        };

        if(typeof testObjecSource.source_settings.list_directories_with_file_network_traffic == 'object' ){
            for (let j=0;  j < testObjecSource.source_settings.list_directories_with_file_network_traffic.length; j++){     
                this.source_settings.list_directories_with_file_network_traffic[j] = testObjecSource.source_settings.list_directories_with_file_network_traffic[j];
            }
        }

        this.description = testObjecSource.description;                                                 
        this.error = this.check(i);
    }


    check(i) {
        let error = false;
        let reg =  new RegExp(/[^a-zA-Z\p{N}]/gui);                                                 // a-Z0-9
        let check =  this.id_division.match(reg);      
        if(check!=null){
            console.log(`В сообщении № ${i} addSource.id_division есть недопустимые символы: ${check}`); 
            error = true;        
        }
        
        reg =  new RegExp(/[^\p{N}]/g);                       //source_id уникальный идентификатор источника (Number) 0-9
        let checkSource_id =  this.source_id.match(reg);      
        if(checkSource_id!=null){
            console.log(`В сообщении № ${i} addSource.source_id есть недопустимые символы: ${checkSource_id}`); 
            error = true;        
        }                                            
                                                    
        reg =  new RegExp(/[^a-zA-Z\p{N}\s_-]/gui);                       //short_name краткое название источника (String) a-Z-_0-9
        let checkShort_name =  this.short_name.match(reg);      
        if(checkShort_name!=null){
            console.log(`В сообщении № ${i} addSource.short_name есть недопустимые символы: ${checkShort_name}`); 
            error = true;        
        }    

     //  network_settings = {                                              // сетевые настройки для доступа к источнику
     //       ipaddress: "",                                          
     //       port: 0,                                                
     //       token_id: "",                                           
     //   };

        reg =  new RegExp(/\d{1,}/g);                                      // ip адрес (String) Проверка ip адреса на корректность             
        let checkIp = this.network_settings.ipaddress.match(reg);
        let errorIp=false;
        if(checkIp.length<5){
            for(let k=0; k<4; k++){
                if(((checkIp[k]>255)||(checkIp[k]<0))){
                errorIp = true;
                }  
            }
        }
        if(errorIp){    
            console.log(`В сообщении № ${i} addSource.network_settings.ipaddress не верно написан: ${this.network_settings.ipaddress}`); 
            error = true;        
        }  

        reg = new RegExp(/[^\p{N}]/gui);                              // сетевой порт (Number) 0-9 и диапазон 1024-65565
        checkShort_name =  this.short_name.match(regShort_name);      
        if(checkShort_name!=null){
            console.log(`В сообщении № ${i} addSource.short_name есть недопустимые символы: ${checkShort_name}`); 
            error = true;        
        }    


        reg =  new RegExp(/[^a-zA-Z\p{N}]/gui);                         // идентификационный токен (String) a-Z0-9
        let checkToken_id =  this.network_settings.token_id.match(reg);      
        if(checkToken_id!=null){
            console.log(`В сообщении № ${i} addSource.network_settings.token_id есть недопустимые символы: ${checkToken_id}`); 
            error = true;        
        }    


     /*   source_settings = {                                       // настройки источника 
            type_architecture_client_server: "",                    
            transmission_telemetry: false,                          
            maximum_number_simultaneous_filtering_processes: 0,     
            type_channel_layer_protocol: "",                        
            list_directories_with_file_network_traffic: [],         // список директорий с файлами сетевого трафика, длинна массива не должна быть 0, массив
                                                                //содержит сторки с символами /\_a-Z0-9
        };
        description = "";     */                                      

        reg =  new RegExp(/[^a-z]/gui);                                 // тип клиент серверной архитектуры (источник работает в режиме клиент или сервер) (String) a-z
        let checkServer =  this.source_settings.type_architecture_client_server.match(reg);      
        if(checkServer!=null){
            console.log(`В сообщении № ${i} addSource.short_name есть недопустимые символы: ${checkServer}`); 
            error = true;        
        }    

        reg =  new RegExp(/[^\p{L}\p{N}\s"'.,()-]/gui);                                         // отправка телеметрии (Bool) BOOL
        let checkTransmission_telemetry =  this.transmission_telemetry.match(reg);      
        if(checkTransmission_telemetry!=null){
            console.log(`В сообщении № ${i} addSource.short_name есть недопустимые символы: ${checkTransmission_telemetry}`); 
            error = true;        
        }    

        reg =  new RegExp(/[^\p{N}]/g);                                                       // максимальное количество одновременных процессов фильтрации (Number) 0-9     
        let checkUnNum =  this.maximum_number_simultaneous_filtering_processes.match(reg);
        if(checkUnNum.length!=null){
            console.log(`В сообщении № ${i} addSource.maximum_number_simultaneous_filtering_processes есть недопустимые символы: ${checkDescription}`); 
            error = true;   
        } 
        else {
            reg =  new RegExp(/\d{1,}/g);                                                 
            let checkNum    =  this.maximum_number_simultaneous_filtering_processes.match(reg);                 //и диапазон 1-10    
            if(((checkNum[0]>10)||(checkNum[0]<1))){
                console.log(`В сообщении № ${i} addSource.maximum_number_simultaneous_filtering_processes есть недопустимые символы: ${checkDescription}`); 
                error = true;  
        }
        }

        reg =  new RegExp(/[^\p{L}\p{N}\s"'.,()-]/gui);                                //! тип протокола канального уровня (String) ip/pppoe (default value = ip) 
        let checkType_channel_layer_protocol =  this.type_channel_layer_protocol.match(reg);      
        if(checkType_channel_layer_protocol!=null){
            console.log(`В сообщении № ${i} addSource.type_channel_layer_protocol есть недопустимые символы: ${checkType_channel_layer_protocol}`); 
            error = true;        
        }    


        let regList =  new RegExp(/[^a-zA-Z_\\\/\p{N}]/gui);                          //содержит сторки с символами /\_a-Z0-9
        if(typeof this.source_settings.list_directories_with_file_network_traffic == 'object' ){
            for (let j=0;  j < this.source_settings.list_directories_with_file_network_traffic.length; j++){     
                
                let checkList =  this.source_settings.list_directories_with_file_network_traffic[j].match(regList);  
                    if(checkList !=null){
                    console.log(`В сообщении № ${i} addSource.source_settings.list_directories_with_file_network_traffic[${j}] есть недопустимые символы: ${checkList}`); 
                    error = true;        
                }
            }
        }

        reg =  new RegExp(/[^\p{L}\p{N}\s"'.,()-]/gui);                                // дополнительное описание (String) а-Я0-9"'.,()-
        let checkDescription =  this.description.match(reg);      
        if(checkDescription!=null){
            console.log(`В сообщении № ${i} addSource.short_name есть недопустимые символы: ${checkDescription}`); 
            error = true;        
        }    

        return error;
    }
}



  
//--------------------------------- Основная ф-ция ----------------------------------------
function exampleUserMessage(){
    console.log("\x1b[32m%s\x1b[0m", "func 'exampleUserMessage', START...\n");

    const EventEmitter = require("events").EventEmitter;
    class MyEventEmitter extends EventEmitter {
        constructor(){
            super();
        }
    }

    const myEventEmitter = new MyEventEmitter();

  //
     //   let org = new addOrganization("Мама-(123), \"Лол\" ?*", "г.Москва, ул. Где-то там, д.4, стр 2");
     //   let errorOrganiz = org.check(); // если есть ошибка то будет true 


   //---------------------------------------- Примеры -----------------------------------------------------    

    const exampleList = [
        {
            testDescription: "Добавляем организацию",
            testObject: {
                name: "ПАО 'Научно исследовательский и конструкторский институт энергетики имени Н.А. Доллежаля'",
                legal_address: "234109 г. Москва, * Варшавское шоссе, д. 38 к.2",
                field_activity: "атомная промышленность",
                division_or_branch_list_id: [],
            },
        },
        {            
            testDescription: "Добавляем организацию",
            testObject: {
                name: "Территориальный* орган федеральной службы государственной статистики по Воронежской области",
                legal_address: "4129 г. Брянск, ул. 50-ти летия октября, д. 11",
                field_activity: "государственный орган",
                division_or_branch_list_id: [],
            },
        },
        {            
            testDescription: "Добавляем организацию, филиала или подразделения организации и настройки источника",
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
                                id_division: "***",
                                source_id: 1000,
                                short_name: "Rosskosmos COD-1",
                                network_settings: { 
                                    ipaddress: "266.123.0.36",
                                    port: 13113,
                                    token_id: "tfeis99nff898449hhgdf",
                                },
                                source_settings: { 
                                    type_architecture_client_server: "client",
                                    transmission_telemetry: false,
                                    maximum_number_simultaneous_filtering_processes: 0,
                                    type_channel_layer_protocol: "",
                                    list_directories_with_file_network_traffic: [
                                        "*/__CURRENT_DISK_1",
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
                                    ipaddress: "69.123.50.255",
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
            testDescription: "Добавляем филиал или подразделение организации",
            testObject: {
                id_organization: "",
                name: "Цех №2 смоленского авиационного завода",
                physical_address: "г. Смоленск, ул. Тараса Шевченко, д. 7, к. 2",
                description: "",
                source_list: [],
            },
        },
        {
            testDescription: "Добавляем настройки источника",
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
                        "*/current_folder_2",
                        "/current_folder_3",
                    ],
                },
                description: "",
            },
        },
    ];
    
    
   /* for (let i=0; i< exampleList.length; i++)
    {
        switch (exampleList[i].testDescription){
       
        case "Добавляем организацию":
            {
              
            }
        case "Добавляем организацию, филиала или подразделения организации и настройки источника":
            {
               // console.log(`Обект № ${i} имя =  ${exampleList[i].testObject}`); 
                let org0 = new organization(exampleList[i].testObject,i);
                break;
            }   
        case "Добавляем филиал или подразделение организации":
            {
                console.log(`Обект № ${i} имя =  ${exampleList[i].testObject}`); 
                let org0 = new addDivision(exampleList[i].testObject,i);
                break;
            }   
        }
    }*/

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
    //console.log(`received a message from the user: ${message}\n`);
    let test       = JSON.parse(message);
    let i          = test.numberMessage;
    let testObject = test.testMessage;
    let err;
     switch ( test.descriptionMessage){
        case "Добавляем организацию":
            {}
        case "Добавляем организацию, филиала или подразделения организации и настройки источника":
            {   // console.log(`Обект № ${i} имя =  ${exampleList[i].testObject}`); 
                let org = new addOrganization(testObject,i);
                break;
            }   
        case "Добавляем филиал или подразделение организации":
            {
                //console.log(`Обект № ${i} имя =  ${testObject}`); 
                let org = new addDivision(testObject,i);
                break;
            }   
        case "Добавляем настройки источника":
            {
                let org = new addSource(testObject,i);
                break;
            }    
        }
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