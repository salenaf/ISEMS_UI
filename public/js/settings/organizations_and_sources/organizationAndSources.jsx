import React from "react";
import ReactDOM from "react-dom";
import { Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateTableSources from "./createTableSources.jsx";
import CreateBodyNewEntity from "./createBodyNewEntity.jsx";
import CreateBodyManagementEntity from "./createBodyManagementEntity.jsx";
import ModalWindowSourceInfo from "../../modal_windows/modalWindowSourceInfo.jsx";
import ModalWindowChangeSource from "../../modal_windows/modalWindowChangeSource.jsx";
import { ModalWindowConfirmMessage } from "../../modal_windows/modalWindowConfirmMessage.jsx";

import { helpers } from "../../common_helpers/helpers.js";

class CreatePageOrganizationAndSources extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "modalWindowSourceDel": false,
            "modalWindowSourceInfo": false,
            "modalWindowChangeSource": false,
            "changeSourceInfoOutput": false,
            "listShortEntity": this.props.listShortEntity,
            "tableSourceList": this.createTableSourceList.call(this, this.props.listShortEntity),
            "checkboxMarkedSourceDel": this.createStateCheckboxMarkedSourceDel.call(this, this.props.listShortEntity.shortListSource),
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
        this.handlerSourceReconnect = this.handlerSourceReconnect.bind(this);

        this.listenerSocketIoConnect.call(this);

        //устанавливаем тему для всех элементов select2
        $.fn.select2.defaults.set("theme", "bootstrap");
    }

    createStateCheckboxMarkedSourceDel(shortListSource){
        let list = {};

        shortListSource.forEach((source) => {
            list[source.source_id] = { 
                checked: false,
                sourceId: source.id,
                divisionId: source.id_division 
            };
        });

        return list;
    }

    listenerSocketIoConnect(){ 
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

        this.props.socketIo.on("module-ni:change status source", (data) => {
            let objCopy = Object.assign({}, this.state);
                
            for(let i = 0; i < objCopy.tableSourceList.length; i++){                  
                if(data.options.sourceID === objCopy.tableSourceList[i].sourceID){
                    objCopy.tableSourceList[i].connectionStatus = data.options.connectStatus;
                    objCopy.tableSourceList[i].connectTime = data.options.connectTime;
                    
                    break;
                }
            }

            this.setState(objCopy);
        });

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

        this.props.socketIo.on("entity: new short source list", (data) => {
            this.setState({ listShortEntity: data.arguments });
            this.setState({ tableSourceList: this.createTableSourceList.call(this, data.arguments) });
            this.setState({ checkboxMarkedSourceDel: this.createStateCheckboxMarkedSourceDel.call(this, data.arguments.shortListSource) });

            this.el = $("#dropdown_all_entity");
            this.el.select2({
                placeholder: "выбор сущности",
                containerCssClass: "input-group input-group-sm",
                width: "auto",
            });
        });
    }

    showModalWindowSourceInfo({ sid, sourceID }){
        this.props.socketIo.emit("entity information", {
            actionType: "get info about source",
            arguments: { entityId: sid },
        });

        this.modalWindowSourceInfoSettings.sourceID = sourceID;
        this.modalWindowSourceInfoSettings.connectionStatus = false;
        this.modalWindowSourceInfoSettings.connectTime = 0;

        for(let i = 0; i < this.state.tableSourceList.length; i++){
            if(this.state.tableSourceList[i].sourceID === sourceID){
                this.modalWindowSourceInfoSettings.connectionStatus = this.state.tableSourceList[i].connectionStatus;
                this.modalWindowSourceInfoSettings.connectTime = this.state.tableSourceList[i].connectTime;

                break;
            }
        }

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
                "connectionStatus": item.connect_status,
                "connectTime": item.connect_time,
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
        let listSourceDel = [];
        for(let id in this.state.checkboxMarkedSourceDel){
            if(this.state.checkboxMarkedSourceDel[id].checked){
                listSourceDel.push({
                    source: id,
                    sourceId: this.state.checkboxMarkedSourceDel[id].sourceId,
                    divisionId: this.state.checkboxMarkedSourceDel[id].divisionId
                });
            }
        }

        this.props.socketIo.emit("delete source info", {
            actionType: "",
            arguments: { listSource: listSourceDel },
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
            return;
        }

        let foldersOnChange = sourceSettings.directoriesNetworkTraffic.onChange;
        //делаем проверку все ли ли параметры валидны
        if(!checkValueIsValid(sourceSettings && !foldersOnChange)){
            return;
        }

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
            objUpdate.sourceSettings.directoriesNetworkTraffic.onChange = true;    
        }

        this.setState(objUpdate);
    }

    handlerSourceReconnect(data){
        this.props.socketIo.emit("reconnect source", { source_id: data.sourceID });
    }

    render(){
        return (
            <React.Fragment>
                <Tabs defaultActiveKey="sources" id="uncontrolled-tab-example">
                    <Tab eventKey="sources" title="источники">
                        <br/>
                        <div className="row mb-2">
                            <div className="col-md-9 text-left text-muted">
                                всего источников: <span className="text-info">{Object.keys(this.state.checkboxMarkedSourceDel).length}</span>
                            </div>
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
                            handlerShowChangeInfo={this.showModalWindowChangeSource} 
                            handlerSourceReconnect={this.handlerSourceReconnect} />
                    </Tab>
                    <Tab eventKey="organization" title="организации / подразделения">
                        <CreateBodyManagementEntity
                            socketIo={this.props.socketIo}
                            listShortEntity={this.state.listShortEntity}
                            listFieldActivity={this.props.listFieldActivity} />
                    </Tab>
                    <Tab eventKey="addElement" title="новая сущность">
                        <CreateBodyNewEntity
                            socketIo={this.props.socketIo} 
                            userPermissions={this.props.userPermissions}
                            listFieldActivity={this.props.listFieldActivity}
                            listShortEntity={this.state.listShortEntity} />
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
};

ReactDOM.render(<CreatePageOrganizationAndSources 
    socketIo={socket}
    listShortEntity={receivedFromServerMain}
    userPermissions={receivedFromServerAccess}
    listFieldActivity={receivedFromServerListFieldActivity} />, document.getElementById("main-page-content"));