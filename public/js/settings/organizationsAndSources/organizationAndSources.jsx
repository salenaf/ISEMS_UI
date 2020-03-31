import React from "react";
import ReactDOM from "react-dom";
import { Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateTableSources from "./createTableSources.jsx";
import CreateBodyNewEntity from "./createBodyNewEntity.jsx";
import CreateBodyManagementEntity from "./createBodyManagementEntity.jsx";
import ModalWindowSourceInfo from "../../modalwindows/modalWindowSourceInfo.jsx";
import ModalWindowChangeSource from "../../modalwindows/modalWindowChangeSource.jsx";
import { ModalWindowConfirmMessage } from "../../modalwindows/modalWindowConfirmMessage.jsx";

import { helpers } from "../../common_helpers/helpers.js";

class CreatePageOrganizationAndSources extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "modalWindowSourceDel": false,
            "modalWindowSourceInfo": false,
            "modalWindowChangeSource": false,
            "changeSourceInfoOutput": false,
            "tableSourceList": this.createTableSourceList.call(this, this.props.listShortEntity),
            "checkboxMarkedSourceDel": this.createStateCheckboxMarkedSourceDel.call(this),
            "sourceSettings": {
                id: "",
                sourceID: {
                    name: "цифровой идентификатор",
                    value: "",
                    isValid: false,
                    isInvalid: false,
                    onChange: false,
                },                    
                shortName: {
                    name: "краткое название источника",
                    value: "",
                    isValid: false,
                    isInvalid: false,
                    onChange: false,
                },
                ipAddress: {
                    name: "ip адрес",
                    value: "",
                    isValid: false,
                    isInvalid: false,
                    onChange: false,
                },
                port: {
                    name: "сетевой порт",
                    value: "",
                    isValid: false,
                    isInvalid: false,
                    onChange: false,
                },
                token: {
                    name: "идентификационный токен",
                    value: "",
                    onChange: false,
                },
                architecture: {
                    name: "архитектура",
                    value: "client",
                    onChange: false,
                },
                maxSimultaneousProc: {
                    name: "параллельные задачи фильтрации",
                    value: 5,
                    onChange: false,
                },
                networkChannel: {
                    name: "тип сетевого канала",
                    value: "",
                    onChange: false,
                },
                telemetry: {
                    name: "телеметрия",
                    value: false,
                    onChange: false,
                },
                directoriesNetworkTraffic: {
                    name: "директории с файлами",
                    isValid: false,
                    isInvalid: false,
                    value: [],
                    onChange: false,
                },
                description: {
                    name: "примечание",
                    value: "",
                    onChange: false,
                },
                newFolder: "",
            },
        };

        this.modalWindowSourceInfoSettings = { data: {}, sourceID: 0 };

        this.listSourceDelete = [];

        this.handlerInput = this.handlerInput.bind(this);
        this.handlerNewFolder = this.handlerNewFolder.bind(this);
        this.generatingNewToken = this.generatingNewToken.bind(this);
        this.handelerFolderDelete = this.handelerFolderDelete.bind(this);
        this.handlerSaveInformation = this.handlerSaveInformation.bind(this);
        this.showModalWindowSourceDel = this.showModalWindowSourceDel.bind(this);
        this.closeModalWindowSourceDel = this.closeModalWindowSourceDel.bind(this);
        this.showModalWindowSourceInfo = this.showModalWindowSourceInfo.bind(this);
        this.closeModalWindowSourceInfo = this.closeModalWindowSourceInfo.bind(this);
        this.showModalWindowChangeSource = this.showModalWindowChangeSource.bind(this);
        this.closeModalWindowChangeSource = this.closeModalWindowChangeSource.bind(this);

        this.changeCheckboxMarkedSourceDel = this.changeCheckboxMarkedSourceDel.bind(this);
        this.handlerSourceDelete = this.handlerSourceDelete.bind(this);

        this.listenerSocketIonConnect.call(this);

        //устанавливаем тему для всех элементов select2
        $.fn.select2.defaults.set("theme", "bootstrap");
    }

    createStateCheckboxMarkedSourceDel(){
        let list = {};

        this.props.listShortEntity.shortListSource.forEach((source) => {
            list[source.source_id] = {
                checked: false,
            };
        });

        return list;
    }

    listenerSocketIonConnect(){ 
        let listElem = [
            "sourceID",
            "shortName",
            "ipAddress",
            "port",
            "token",
            "architecture",
            "maxSimultaneousProc",
            "networkChannel",
            "telemetry",
            "directoriesNetworkTraffic",
            "description"
        ];

        this.props.socketIo.on("entity: set info only source", (data) => {
            let stateCopy = Object.assign({}, this.state);

            stateCopy.sourceSettings.id = data.arguments.id;
            stateCopy.sourceSettings.sourceID.value = data.arguments.source_id;
            stateCopy.sourceSettings.shortName.value = data.arguments.short_name;
            stateCopy.sourceSettings.ipAddress.value = data.arguments.network_settings.ipaddress;
            stateCopy.sourceSettings.port.value = data.arguments.network_settings.port;
            stateCopy.sourceSettings.token.value = data.arguments.network_settings.token_id;
            stateCopy.sourceSettings.architecture.value = data.arguments.source_settings.type_architecture_client_server;
            stateCopy.sourceSettings.maxSimultaneousProc.value = data.arguments.source_settings.maximum_number_simultaneous_filtering_processes;
            stateCopy.sourceSettings.networkChannel.value = data.arguments.source_settings.type_channel_layer_protocol;
            stateCopy.sourceSettings.telemetry.value = data.arguments.source_settings.transmission_telemetry;
            stateCopy.sourceSettings.directoriesNetworkTraffic.value = data.arguments.source_settings.list_directories_with_file_network_traffic;
            stateCopy.sourceSettings.description.value = data.arguments.description;

            listElem.forEach((item) => {
                if(typeof stateCopy.sourceSettings[item] !== "undefined"){
                    if(typeof stateCopy.sourceSettings[item].isValid !== "undefined"){
                        stateCopy.sourceSettings[item].isValid = false;
                    }
                    if(typeof stateCopy.sourceSettings[item].isInvalid !== "undefined"){
                        stateCopy.sourceSettings[item].isInvalid = false;
                    }
                    if(typeof stateCopy.sourceSettings[item].onChange !== "undefined"){
                        stateCopy.sourceSettings[item].onChange = false;
                    }
                }
            });

            this.setState(stateCopy);

            this.setState({ changeSourceInfoOutput: true });
        });

        this.props.socketIo.on("entity: new short source list", (date) => {
            let stateCopy = Object.assign({}, this.state);
            stateCopy.tableSourceList = this.createTableSourceList.call(this, date.arguments);
            
            this.setState(stateCopy);
        });
    }

    showModalWindowSourceInfo({ sid, sourceID }){
        this.props.socketIo.emit("entity information", {
            actionType: "get info about source",
            arguments: { entityId: sid },
        });

        this.modalWindowSourceInfoSettings.sourceID = sourceID;

        this.setState({"modalWindowSourceInfo": true});
    }

    closeModalWindowSourceInfo(){
        this.setState({"modalWindowSourceInfo": false});
    }

    showModalWindowChangeSource({ sid, sourceID }){
        this.props.socketIo.emit("entity information", {
            actionType: "get info only source",
            arguments: { entityId: sid },
        });

        this.modalWindowSourceInfoSettings.sourceID = sourceID;

        this.setState({"modalWindowChangeSource": true});
    }

    closeModalWindowChangeSource(){
        this.setState({ "modalWindowChangeSource": false });
        this.setState({ "changeSourceInfoOutput": false });
    }

    showModalWindowSourceDel(){
        this.listSourceDelete = [];

        for(let id in this.state.checkboxMarkedSourceDel){
            if(this.state.checkboxMarkedSourceDel[id].checked){
                this.listSourceDelete.push(id);
            }
        }

        if(this.listSourceDelete.length === 0) return;

        this.setState({ "modalWindowSourceDel": true });
    }

    closeModalWindowSourceDel(){
        this.setState({ "modalWindowSourceDel": false });
    }

    changeCheckboxMarkedSourceDel(sourceID){
        let stateCopy = Object.assign({}, this.state);
        stateCopy.checkboxMarkedSourceDel[sourceID].checked = !this.state.checkboxMarkedSourceDel[sourceID].checked;
        this.setState(stateCopy);
    }

    createTableSourceList(listShortEntity){
        let newList = listShortEntity.shortListSource.map((item) => {
            let field = "";
            listShortEntity.shortListDivision.forEach((i) => {
                if(i.id === item.id_division){
                    listShortEntity.shortListOrganization.forEach((e) => {
                        if(e.id === i.id_organization){
                            field = e.field_activity;
                        }
                    });
                }
            });

            return {
                "sourceID": item.source_id,
                "sid": item.id,
                "shortName": item.short_name,
                "dateRegister": item.date_register,
                "fieldActivity": field,
                "versionApp": item.information_about_app.version,
                "releaseApp": item.information_about_app.date,
                "connectionStatus": false,
            };
        });

        newList.sort((a, b) => {
            if (a.sourceID > b.sourceID) return 1;
            if (a.sourceID == b.sourceID) return 0;
            if (a.sourceID < b.sourceID) return -1;
        });

        return newList;
    }

    handlerSourceDelete(){
        console.log(`УДАЛЯЕМ ИСТОЧНИКИ № ${this.listSourceDelete}`);

        this.props.socketIo.emit("delete source info", {
            actionType: "",
            arguments: { listSource: this.listSourceDelete },
        });

        this.setState({ "modalWindowSourceDel": false });
    }

    isDisabledDelete(typeButton){
        if(!this.props.userPermissions.management_sources.element_settings.delete.status){
            return "disabled";
        }

        let isChecked = false;
        let settings = {
            "sourceDel": this.state.checkboxMarkedSourceDel,
        };

        for(let id in settings[typeButton]){
            if(settings[typeButton][id].checked){
                isChecked = true;

                break;
            }
        }

        return (isChecked) ? "" : "disabled";
    }

    generatingNewToken(){
        let stateCopy = Object.assign({}, this.state);
        stateCopy.sourceSettings.token.value = helpers.tokenRand();
        stateCopy.sourceSettings.token.onChange = true;
        this.setState(stateCopy);
    }

    handlerInput(e){       
        let elementName = e.target.id;
        let value = e.target.value;

        console.log("func 'handlerInput', START...");
        console.log(`elemID: ${elementName}, elemValue: ${value}`);
        console.log(e.target.value);

        const listElem = {
            "source_id": {
                name: "sourceID",
                pattern: "hostID",
            },
            "source_short_name": {
                name: "shortName",
                pattern: "shortNameHost",
            }, 
            "source_ip": {
                name: "ipAddress",
                pattern: "ipaddress",
            },
            "source_port": {
                name: "port",
                pattern: "port",
            }, 
            "input_folder": {
                name: "directoriesNetworkTraffic",
                pattern: "folderStorage",
            },
            "source_description": {
                name: "description",
                pattern: "",
            },
            "source_telemetry": {
                name: "telemetry",
                pattern: "",
            },
            "source_network_channel": {
                name: "networkChannel",
                pattern: "",
            },
            "source_architecture": {
                name: "architecture",
                pattern: "",
            },
            "source_max_simultaneous_proc": {
                name: "maxSimultaneousProc",
                pattern: "",
            }, 
        };

        let listSelectors = [
            "source_description",
            "source_telemetry",
            "source_network_channel",
            "source_architecture",
            "source_max_simultaneous_proc", 
        ];

        let objUpdate = Object.assign({}, this.state);

        console.log(objUpdate.sourceSettings);

        if(listSelectors.includes(elementName)){
            if(elementName === "source_telemetry"){
                objUpdate.sourceSettings[listElem[elementName].name].value = e.target.checked;    
            } else {
                objUpdate.sourceSettings[listElem[elementName].name].value = value;    
            }

            objUpdate.sourceSettings[listElem[elementName].name].onChange = true;    
            this.setState(objUpdate);
    
            return;
        }

        console.log(`value: ${value}, reg res: '${helpers.checkInputValidation({name: listElem[elementName].pattern, value: value })}' |${listElem[elementName].pattern}|`);

        if(!helpers.checkInputValidation({name: listElem[elementName].pattern, value: value })){
            objUpdate.sourceSettings[listElem[elementName].name].isValid = false;
            objUpdate.sourceSettings[listElem[elementName].name].isInvalid = true;
        } else {
            if(elementName === "input_folder"){
                objUpdate.sourceSettings.newFolder = value;        
            } else {
                objUpdate.sourceSettings[listElem[elementName].name].value = value;
                objUpdate.sourceSettings[listElem[elementName].name].onChange = true;
            }

            objUpdate.sourceSettings[listElem[elementName].name].isValid = true;
            objUpdate.sourceSettings[listElem[elementName].name].isInvalid = false;
        }

        this.setState(objUpdate);
    }

    handlerNewFolder(){
        let newFolder = this.state.sourceSettings.newFolder.trim();
        let dirNetTraff = this.state.sourceSettings.directoriesNetworkTraffic;
        if(dirNetTraff.isInvalid){
            return;
        }

        if(newFolder.length < 2){

            return;
        }

        if(newFolder[0] !== "/"){
            newFolder = "/"+newFolder;
        }

        //ищем подобный элемент
        if(dirNetTraff.value.includes(newFolder)){
            return;
        }

        let objUpdate = Object.assign({}, this.state);        

        objUpdate.sourceSettings.directoriesNetworkTraffic.value.push(newFolder);
        objUpdate.sourceSettings.newFolder = "";
        objUpdate.sourceSettings.directoriesNetworkTraffic.isValid = false;
        objUpdate.sourceSettings.directoriesNetworkTraffic.isInvalid = false;
        objUpdate.sourceSettings.directoriesNetworkTraffic.onChange = true;    

        this.setState( objUpdate );

        document.getElementById("input_folder").value = "";
    }

    handlerSaveInformation(){
        console.log("func 'handlerSaveInformation', START...");

        function checkValueChange(list){
            let isChange = false;

            let range = (list)=>{
                for(let key in list){
                    if((key === "onChange") && (list[key])){
                        isChange = true;

                        break;
                    }

                    if({}.toString.call(list[key]).slice(8, -1) === "Object"){                      
                        range(list[key]);
                    }
                }
            };

            range(list);

            return isChange;
        }

        function checkValueIsValid(list){
            let isValid = true;

            let range = (list)=>{
                for(let key in list){
                    if((key === "isValid") && (!list[key]) && (list.onChange)){
                        isValid = false;

                        break;
                    }

                    if({}.toString.call(list[key]).slice(8, -1) === "Object"){                      
                        range(list[key]);
                    }
                }
            };

            range(list);

            return isValid;
        }

        let sourceSettings = this.state.sourceSettings;

        //делаем проверку были ли какие либо изменения в информации по источнику
        if(!checkValueChange(sourceSettings)){
            console.log("Ни каких изменений в информации по источнику сделано не было");

            return;
        }

        let foldersOnChange = sourceSettings.directoriesNetworkTraffic.onChange;
        //делаем проверку все ли ли параметры валидны
        if(!checkValueIsValid(sourceSettings && !foldersOnChange)){
            console.log("Один или более заданных парамеров не валидны");

            return;
        }

        console.log("передаем информацию о новом источнике в БД");

        let s = this.state.sourceSettings;

        this.props.socketIo.emit("change source info", {
            id: s.id,
            source_id: s.sourceID.value,
            short_name: s.shortName.value,
            description: s.description.value,
            network_settings: {
                ipaddress: s.ipAddress.value,
                port: s.port.value,
                token_id: s.token.value,
            },
            source_settings: {
                list_directories_with_file_network_traffic: s.directoriesNetworkTraffic.value,
                type_architecture_client_server: s.architecture.value,
                transmission_telemetry: s.telemetry.value,
                maximum_number_simultaneous_filtering_processes: s.maxSimultaneousProc.value,
                type_channel_layer_protocol: s.networkChannel.value,
            },
        });

        this.closeModalWindowChangeSource();
    }

    handelerFolderDelete(nameFolder){
        let objUpdate = Object.assign({}, this.state);        
        let list = objUpdate.sourceSettings.directoriesNetworkTraffic.value;
        objUpdate.sourceSettings.directoriesNetworkTraffic.value = list.filter((item) => (item !== nameFolder));

        if(list.length !== objUpdate.sourceSettings.directoriesNetworkTraffic.value.length){
            console.log(`count before folder: '${list.length}', count folder after ${objUpdate.sourceSettings.directoriesNetworkTraffic.value.length}`);

            objUpdate.sourceSettings.directoriesNetworkTraffic.onChange = true;    
        }

        this.setState(objUpdate);
    }

    render(){
        return (
            <React.Fragment>
                <Tabs defaultActiveKey="sources" id="uncontrolled-tab-example">
                    <Tab eventKey="sources" title="источники">
                        <br/>
                        <div className="row">
                            <div className="col-md-9 text-left">Всего источников: {Object.keys(this.state.checkboxMarkedSourceDel).length}</div>
                            <div className="col-md-3 text-right">
                                <Button 
                                    variant="outline-danger" 
                                    onClick={this.showModalWindowSourceDel}
                                    disabled={this.isDisabledDelete.call(this, "sourceDel")}
                                    size="sm">удалить</Button>
                            </div>
                        </div>
                        <CreateTableSources 
                            userPermissions={this.props.userPermissions}
                            tableSourceList={this.state.tableSourceList}
                            changeCheckboxMarked={this.changeCheckboxMarkedSourceDel}
                            handlerShowInfoWindow={this.showModalWindowSourceInfo}
                            handlerShowChangeInfo={this.showModalWindowChangeSource} />
                    </Tab>
                    <Tab eventKey="organization" title="организации / подразделения">
                        {/** 
                        Здесть тоже используется объект listSourcesInformation, соответственно в PRODUCTION 
                        тоже должен быть отдельный объект 
                        */}
                        <CreateBodyManagementEntity
                            listFieldActivity={this.props.listFieldActivity} 
                            listSourcesInformation={this.props.listSourcesInformation}
                            listSourcesFullInformation={this.props.listSourcesFullInformation}/>
                    </Tab>
                    <Tab eventKey="addElement" title="новая сущность">
                        
                        {/** 
                            Затенять и делать не активным, при запрете группе добавлять новые сущности 
                        
                        На основе объекта listSourcesInformation в классе CreateBodyNewEntity формируется
                        перечень организаций и подразделений в выпадающем списке, однако listSourcesInformation
                        на прямую зависит от источнико, если источника нет то и в списке listSourcesInformation
                        его не будет, хотя должны быть Организация и Подразделение которых тоже не будет.
                        По этому, а PRODUCTION похоже нужен отдельный список Организаций и Подразделений получаемый с сервера
                        */}
                        
                        <CreateBodyNewEntity 
                            userPermissions={this.props.userPermissions}
                            listFieldActivity={this.props.listFieldActivity}
                            listShortEntity={this.props.listShortEntity} />
                    </Tab>
                </Tabs>
                <ModalWindowSourceInfo 
                    show={this.state.modalWindowSourceInfo}
                    onHide={this.closeModalWindowSourceInfo}
                    socketIo={this.props.socketIo}
                    settings={this.modalWindowSourceInfoSettings} />
                <ModalWindowChangeSource                     
                    show={this.state.modalWindowChangeSource}
                    onHide={this.closeModalWindowChangeSource}
                    socketIo={this.props.socketIo}
                    settings={this.modalWindowSourceInfoSettings}
                    isShowInfo={this.state.changeSourceInfoOutput} 
                    addNewFolder={this.handlerNewFolder}
                    handlerInput={this.handlerInput} 
                    storageInput={this.state.sourceSettings}
                    generatingNewToken={this.generatingNewToken}
                    handelerFolderDelete={this.handelerFolderDelete}
                    handlerSaveInformation={this.handlerSaveInformation} />
                <ModalWindowConfirmMessage 
                    show={this.state.modalWindowSourceDel}
                    onHide={this.closeModalWindowSourceDel}
                    msgBody={`Вы действительно хотите удалить ${(this.listSourceDelete.length > 1) ? "источники с номерами": "источник с номером"} ${this.listSourceDelete}`}
                    msgTitle={"Удаление"}
                    nameDel={this.listSourceDelete.join()}
                    handlerConfirm={this.handlerSourceDelete} />
            </React.Fragment>
        );
    }
}

CreatePageOrganizationAndSources.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listShortEntity: PropTypes.object.isRequired,
    userPermissions: PropTypes.object.isRequired,
    listFieldActivity: PropTypes.array.isRequired,

    listSourcesFullInformation: PropTypes.object,
    listSourcesInformation: PropTypes.object.isRequired,
    listDivisionInformation: PropTypes.array.isRequired,
};

let listSourcesInformation = {
    100: {
        "sid": "ffeo0393f94h8884h494g4g",
        "did": "dnjdjdnuw82hd8h882h82h8h",
        "oid": "cnw9w9dj93d8383d8h38d83f4",
        "shortName": "RosAtom COD 1",
        "dateRegister": "2019-08-13 14:39:08",
        "fieldActivity": "атомная промышленность",
        "division": "Центр обработки данных №1",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    102: {
        "sid": "bmfomr94jbv4nrb949gh94g994",
        "did": "vm93j9939f9933993uf9rrrrr",
        "oid": "cnw9w9dj93d8383d8h38d83f4",
        "shortName": "RosAtom COD 2",
        "dateRegister": "2020-01-13 10:13:00",
        "fieldActivity": "атомная промышленность",
        "division": "Центр обработки данных №2",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    106: {
        "sid": "nx0j29jf993h88v84g84gf8asa",
        "did": "vievieivihf83h38f838hfh3f8",
        "oid": "cne8h8h828882yfd337fg3g838",
        "shortName": "RosCosmos COD 1",
        "fieldActivity": "космическая промышленность",
        "dateRegister": "2019-11-12 01:35:18",
        "division": "Центр обработки данных №2",
        "organization": "Государственная корпорация по космической деятельности \"РОСКОСМОС\"",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    103: {
        "sid": "xjn99393ru93ru9439r93ur933",
        "did": "nwc99983883h8hrf38fh83f383",
        "oid": "cnw89h8dh38h8h38fhd838f83",
        "shortName": "UMCHS Belgorod",
        "dateRegister": "2019-12-16 18:03:20",
        "fieldActivity": "органы безопасности",
        "division": "Управление МЧС России по Белгородской области",
        "organization": "МЧС России",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    104: {
        "sid": "n9j0j349849ur8u8488384833",
        "did": "xaja9ja9j9j93j380aj016d25",
        "oid": "cnw89h8dh38h8h38fhd838f83",
        "shortName": "UMCHS Tambov",
        "dateRegister": "2019-08-13 16:19:59",
        "fieldActivity": "органы безопасности",
        "division": "Управление МЧС России по Тамбовской области",
        "organization": "МЧС России",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
    1015: {
        "sid": "vm0pc0fff3933030jr0i34344",
        "did": "dwj289j38838r8r8838r3r393",
        "oid": "dj929d29euu93438r84r49392",
        "shortName": "DZO Briansk",
        "dateRegister": "2019-02-30 07:49:48",
        "fieldActivity": "государственные органы",
        "division": "Департамент здравоохранения Брянской области",
        "organization": "Департамент здравоохранения",
        "versionApp": "v1.4.4",
        "releaseApp": "12.12.2019",
    },
};

let listSourcesFullInformation = {
    100: {
        "id": "ffeo0393f94h8884h494g4g",
        "did": "dnjdjdnuw82hd8h882h82h8h",
        "oid": "cnw9w9dj93d8383d8h38d83f4",
        "shortName": "RosAtom COD 1",
        "dateRegister": "2019-08-13 14:39:08",
        "dateChange": "2020-01-02 10:45:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Центр обработки данных №1",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Москва, ул. Удальцова, д.3",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 1,
        },
        "organization": {
            "name": "Государственная корпорация атомной энергии Росатом",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "атомная промышленность",
            "legalAddress": "123482 г. Москва, Дмитровское шоссе, д. 67, к. 3",
            "countDivision": 1,
        },
        "networkSettings": { 
            "ip": "12.63.55.9", 
            "port": 13113, 
            "tokenID": "ffffoeo39fj94j949tj949j94j9tj4t", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 3,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__CURRENT_DISK_1","/__CURRENT_DISK_2", "/__CURRENT_DISK_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    102: {
        "id": "bmfomr94jbv4nrb949gh94g994",
        "did": "vm93j9939f9933993uf9rrrrr",
        "oid": "cnw9w9dj93d8383d8h38d83f4",
        "shortName": "RosAtom COD 2",
        "dateRegister": "2020-01-13 10:13:00",
        "dateChange": "2020-01-02 10:45:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Центр обработки данных №2",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Москва, ул. Щербаковская, д.13",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 3,
        },
        "organization": {
            "name": "Государственная корпорация атомной энергии Росатом",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "атомная промышленность",
            "legalAddress": "123482 г. Москва, Дмитровское шоссе, д. 67, к. 3",
            "countDivision": 1,
        },
        "networkSettings": { 
            "ip": "235.163.50.19", 
            "port": 13113, 
            "tokenID": "vndoonvnnnd2dnsnd92enbbr3", 
        },
        "sourceSettings": {
            "architecture": "server",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__CURRENT_DISK_1","/__CURRENT_DISK_2", "/__CURRENT_DISK_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    106: {
        "id": "nx0j29jf993h88v84g84gf8asa",
        "did": "vievieivihf83h38f838hfh3f8",
        "oid": "cne8h8h828882yfd337fg3g838",
        "shortName": "RosCosmos COD 1",
        "dateRegister": "2019-01-12 13:13:13",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Центр обработки данных №1",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Москва, ул. Удальцова, д.3",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 1,
        },
        "organization": {
            "name": "Государственная корпорация по космической деятельности \"РОСКОСМОС\"",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "космическая промышленность",
            "legalAddress": "123482 г. Москва, Ленинский пр., д. 100, к. 1",
            "countDivision": 2, 
        },
        "networkSettings": { 
            "ip": "89.13.115.129", 
            "port": 13113, 
            "tokenID": "fckf0k034r0f949h93h3tt4", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__CURRENT_DISK_1","/__CURRENT_DISK_2", "/__CURRENT_DISK_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    103: {
        "id": "xjn99393ru93ru9439r93ur933",
        "did": "nwc99983883h8hrf38fh83f383",
        "oid": "cnw89h8dh38h8h38fhd838f83",
        "shortName": "UMCHS Belgorod",
        "dateRegister": "2019-12-16 18:03:20",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Управление МЧС России по Белгородской области",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Белгород, ул. Ленина, д.3",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 2,
        },
        "organization": {
            "name": "МЧС России",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "органы безопасности",
            "legalAddress": "123482 г. Москва, пр. Мира, д. 4, к. 1",
            "countDivision": 3,
        },
        "networkSettings": { 
            "ip": "32.56.4.44", 
            "port": 13113, 
            "tokenID": "jfj29ewj9u93r3rfvefefr3r33", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__folder_1","/__folder_2", "/__folder_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    104: {
        "id": "n9j0j349849ur8u8488384833",
        "did": "xaja9ja9j9j93j380aj016d25",
        "oid": "cnw89h8dh38h8h38fhd838f83",
        "shortName": "UMCHS Tambov",
        "dateRegister": "2019-08-13 16:19:59",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Управление МЧС России по Тамбовской области",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Тамбов, ул. 1-ого Мая, д.13",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 1,
        },
        "organization": {
            "name": "МЧС России",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "органы безопасности",
            "legalAddress": "123482 г. Москва, пр. Мира, д. 4, к. 1",
            "countDivision": 1,
        },
        "networkSettings": { 
            "ip": "56.123.3.11", 
            "port": 13113, 
            "tokenID": "cmoocw00f39f39f93320j0f2", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__folder_1","/__folder_2", "/__folder_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
    1015: {
        "id": "vm0pc0fff3933030jr0i34344",
        "did": "dwj289j38838r8r8838r3r393",
        "oid": "dj929d29euu93438r84r49392",
        "shortName": "DZO Briansk",
        "dateRegister": "2019-02-30 07:49:48",
        "dateChange": "2020-01-01 08:15:43",
        "description": "какие то замечания или описание об источнике...",
        "division": {
            "name": "Департамент здравоохранения Брянской области",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Брянск, ул. Возрождения, д.20",
            "description": "какие то замечания или описание по подразделению...",
            "countSources": 2,
        },
        "organization": {
            "name": "Департамент здравоохранения",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "государственные органы",
            "legalAddress": "123482 г. Москва, ул. Зорге, д. 14",
            "countDivision": 2, 
        },
        "networkSettings": { 
            "ip": "56.123.3.11", 
            "port": 13113, 
            "tokenID": "cmoocw00f39f39f93320j0f2", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 4,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__custom_1","/__custom_2", "/__custom_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
};

let listDivisionInformation = [
    {
        "id": "jcj992h9e92h9hf948hf94",
        "divisionName": "Департамент здравоохранения Брянской области",
        "organization": "Департамент здравоохранения",
        "dateRegister": "2019-04-13 11:49:24",
        "countSources": 2
    },
    {
        "id": "cn983jd939h84f849fh3rr3",
        "divisionName": "Управление МЧС России по Тамбовской области",
        "organization": "МЧС России",
        "dateRegister": "2019-10-23 11:08:24",
        "countSources": 1
    },
    {
        "id": "cn38rr9u39u39499349uf9",
        "divisionName": "Управление МЧС России по Белгородской области",
        "organization": "МЧС России",
        "dateRegister": "2019-05-14 09:43:21",
        "countSources": 1
    },
    {
        "id": "m09j92e93u8e3u39ur99uf9",
        "divisionName": "Центр обработки данных №2",
        "organization": "Государственная корпорация по космической деятельности \"РОСКОСМОС\"",
        "dateRegister": "2019-05-14 19:23:42",
        "countSources": 1
    },
    {
        "id": "m9wjd9j9d29934949r9d9w",
        "divisionName": "Центр обработки данных №1",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "dateRegister": "2020-01-14 14:23:42",
        "countSources": 1
    },
    {
        "id": "ffej9jf39j03i0ir40i3434",
        "divisionName": "Центр обработки данных №2",
        "organization": "Государственная корпорация атомной энергии Росатом",
        "dateRegister": "2020-01-14 14:23:42",
        "countSources": 1
    },
];

ReactDOM.render(<CreatePageOrganizationAndSources 
    socketIo={socket}
    listShortEntity={receivedFromServerMain}
    userPermissions={receivedFromServerAccess}
    listFieldActivity={receivedFromServerListFieldActivity}

    listSourcesFullInformation={listSourcesFullInformation}
    listSourcesInformation={listSourcesInformation}
    listDivisionInformation={listDivisionInformation} />, document.getElementById("main-page-content"));