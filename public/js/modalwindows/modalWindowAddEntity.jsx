"use strict";

import React from "react";
import { Button, Col, Form, FormControl, Row, Modal, InputGroup } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "../common_helpers/helpers.js";

class ListFolder extends React.Component {
    constructor(props){
        super(props);

        this.listFolders = this.listFolders.bind(this);        
    }

    deleteNewFolder(folderName){
        this.props.handelerFolderDelete(folderName);
    }

    listFolders(){
        return this.props.directoriesNetworkTraffic.map((item) => {
            let num = 0;
            return (
                <li key={`new_folder_${item}_${num++}`}>
                    {item}&nbsp;
                    <a onClick={this.deleteNewFolder.bind(this, item)} className="close" href="#"><img src="./images/icons8-delete-16.png"></img></a>
                </li>)
            ;
        });
    }

    render(){
        return <ol>{this.listFolders()}</ol>;
    }
}

ListFolder.propTypes = {
    handelerFolderDelete: PropTypes.func.isRequired,
    directoriesNetworkTraffic: PropTypes.array.isRequired,
};

class CreateBodyOrganization extends React.Component {
    constructor(props){
        super(props);
    }

    createListFieldActivity(){
        let list = Object.keys(this.props.listFieldActivity);
        list.sort();

        let num = 1;
        return (
            <Form.Group>
                <Form.Label>Вид деятельности</Form.Label>
                <Form.Control 
                    as="select" 
                    size="sm"
                    id="organization_field_selector" 
                    isValid={this.props.storageInput.fieldActivity.isValid}
                    isInvalid={this.props.storageInput.fieldActivity.isInvalid} 
                    onChange={this.props.handlerInput.bind(this, "organization")} >
                    <option value="" key="list_field_activity_0">...</option>
                    {list.map((item) => <option value={item} key={`list_field_activity_${num++}`}>{item}</option>)}
                </Form.Control>
            </Form.Group>
        );         
    }

    render(){
        return (
            <Form>
                <Form.Group>
                    <Form.Label>Название организации</Form.Label>
                    <Form.Control 
                        type="text" 
                        id="organization_name"
                        isValid={this.props.storageInput.organizationName.isValid}
                        isInvalid={this.props.storageInput.organizationName.isInvalid} 
                        onChange={this.props.handlerInput.bind(this, "organization")} />
                </Form.Group>
                {this.createListFieldActivity.call(this)}
                <Form.Group>
                    <Form.Label>Юридический адрес</Form.Label>
                    <Form.Control 
                        as="textarea" 
                        rows="2" 
                        id="legal_address" 
                        isValid={this.props.storageInput.legalAddress.isValid}
                        isInvalid={this.props.storageInput.legalAddress.isInvalid}
                        onChange={this.props.handlerInput.bind(this, "organization")} />
                </Form.Group>
            </Form>
        );
    }
}

CreateBodyOrganization.propTypes = {
    handlerInput: PropTypes.func.isRequired,
    storageInput: PropTypes.object.isRequired,
    listFieldActivity: PropTypes.object.isRequired,
};

class CreateBodyDivision extends React.Component {
    constructor(props){
        super(props);
    }
    
    render(){
        return (
            <Form>
                <Form.Group>
                    <Form.Label>Название подразделения или филиала</Form.Label>
                    <Form.Control 
                        type="text" 
                        id="division_name"
                        isValid={this.props.storageInput.divisionName.isValid}
                        isInvalid={this.props.storageInput.divisionName.isInvalid}
                        onChange={this.props.handlerInput.bind(this, "division")} />
                </Form.Group>
                <Form.Group>
                    <Form.Label>Физический адрес</Form.Label>
                    <Form.Control 
                        as="textarea" 
                        id="division_physical_address" 
                        rows="2"
                        isValid={this.props.storageInput.physicalAddress.isValid}
                        isInvalid={this.props.storageInput.physicalAddress.isInvalid}
                        onChange={this.props.handlerInput.bind(this, "division")} />
                </Form.Group>
                <Form.Group>
                    <Form.Label>Примечание</Form.Label>
                    <Form.Control 
                        as="textarea" 
                        id="division_description" 
                        rows="3"
                        onChange={this.props.handlerInput.bind(this, "division")} />
                </Form.Group>
            </Form>
        );
    }
}

CreateBodyDivision.propTypes = {
    handlerInput: PropTypes.func.isRequired,
    storageInput: PropTypes.object.isRequired,
};

class CreateBodySource extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <Form validated={false}>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Источник</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl 
                        id="source_id" 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.sourceID.isValid}
                        isInvalid={this.props.storageInput.sourceID.isInvalid}
                        placeholder="цифровой идентификатор" />
                    <FormControl 
                        id="source_short_name" 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.shortName.isValid}
                        isInvalid={this.props.storageInput.shortName.isInvalid}
                        placeholder="краткое название (анг. алфавит)" />               
                </InputGroup>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Сетевые настройки</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl 
                        id="source_ip" 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.ipAddress.isValid}
                        isInvalid={this.props.storageInput.ipAddress.isInvalid}
                        placeholder="ip адрес" />
                    <FormControl 
                        id="source_port" 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.port.isValid}
                        isInvalid={this.props.storageInput.port.isInvalid}
                        placeholder="сетевой порт" />
                </InputGroup>
                <Form.Row>
                    <Form.Group as={Col}>
                        <Form.Label>Архитектура</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.architecture.isValid}
                            isInvalid={this.props.storageInput.architecture.isInvalid}
                            id="source_architecture" 
                            as="select" 
                            size="sm"
                            defaultValue="client">
                            <option value="client">клиент</option>
                            <option value="server">сервер</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col}>
                        <Form.Label>Параллельные задачи фильтрации</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.maxSimultaneousProc.isValid}
                            isInvalid={this.props.storageInput.maxSimultaneousProc.isInvalid}
                            id="source_max_simultaneous_proc" 
                            as="select" 
                            size="sm"
                            defaultValue="5">
                            {(() => {
                                let list = [];
                                for(let i = 1; i <= 10; i++){
                                    list.push(<option value={i} key={`tfo_${i}`}>{i}</option>);
                                }

                                return list;
                            })()
                            }
                        </Form.Control>
                    </Form.Group>
                </Form.Row>
                <Form.Row>
                    <Form.Group as={Col} lg={3}>
                        <Form.Label>Тип сетевого канала</Form.Label>
                        <Form.Control 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.networkChannel.isValid}
                            isInvalid={this.props.storageInput.networkChannel.isInvalid}
                            id="source_network_channel"
                            as="select" 
                            size="sm"
                            defaultValue="ip">
                            <option value="ip">ip/vlan</option>
                            <option value="pppoe">pppoe</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col} lg={9}>
                        <Form.Label>Идентификационный токен</Form.Label>
                        <Form.Control id="source_token" type="text" readOnly defaultValue={this.props.storageInput.token.value} />
                    </Form.Group>
                </Form.Row>
                <Row>
                    <Col lg={4}>
                        <Form.Check 
                            onChange={this.props.handlerInput.bind(this, "source")}
                            isValid={this.props.storageInput.telemetry.isValid}
                            isInvalid={this.props.storageInput.telemetry.isInvalid}
                            type="switch"
                            id="source_telemetry" 
                            label="телеметрия"
                        />
                    </Col>
                    <Col lg={8}>
                        <InputGroup className="mb-3">
                            <FormControl
                                id="input_folder"
                                onChange={this.props.handlerInput.bind(this, "source")}
                                isValid={this.props.storageInput.directoriesNetworkTraffic.isValid}
                                isInvalid={this.props.storageInput.directoriesNetworkTraffic.isInvalid}
                                placeholder="полный путь до директории с файлами" />
                            <InputGroup.Append>
                                <Button onClick={this.props.addNewFolder} variant="outline-secondary">применить</Button>
                            </InputGroup.Append>
                        </InputGroup>
                    </Col>
                </Row>
                <Row>
                    <Col lg={4}></Col>
                    <Col lg={8}>
                        <ListFolder 
                            handelerFolderDelete={this.props.handelerFolderDelete}
                            directoriesNetworkTraffic={this.props.storageInput.directoriesNetworkTraffic.value} />
                    </Col>
                </Row>
                <Form.Group>
                    <Form.Label>Примечание</Form.Label>
                    <Form.Control 
                        onChange={this.props.handlerInput.bind(this, "source")}
                        isValid={this.props.storageInput.description.isValid}
                        isInvalid={this.props.storageInput.description.isInvalid}
                        id="source_description" 
                        as="textarea" 
                        rows="3" />
                </Form.Group>
            </Form>
        );
    }
}

CreateBodySource.propTypes = {
    addNewFolder: PropTypes.func.isRequired,
    handlerInput: PropTypes.func.isRequired, 
    storageInput: PropTypes.object.isRequired,
    handelerFolderDelete: PropTypes.func.isRequired,
};

class CreateModalBody extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        switch(this.props.typeModalBody){
        case "organization":
            return <CreateBodyOrganization 
                handlerInput={this.props.handlerInput} 
                storageInput={this.props.storageInput.organizationSettings}
                listFieldActivity={this.props.listFieldActivity} />;

        case "division":
            return <CreateBodyDivision 
                handlerInput={this.props.handlerInput} 
                storageInput={this.props.storageInput.divisionSettings} />;

        case "source":
            return <CreateBodySource 
                addNewFolder={this.props.addNewFolder}
                handlerInput={this.props.handlerInput} 
                storageInput={this.props.storageInput.sourceSettings} 
                handelerFolderDelete={this.props.handelerFolderDelete} />;

        default: 
            return;
        }
    }
}

CreateModalBody.propTypes = {
    addNewFolder: PropTypes.func.isRequired,
    handlerInput: PropTypes.func.isRequired,
    storageInput: PropTypes.object.isRequired,
    typeModalBody: PropTypes.string,
    listFieldActivity: PropTypes.object.isRequired,
    handelerFolderDelete: PropTypes.func.isRequired,
};

export default class ModalWindowAddEntity extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            modalBodySettings: {
                organizationSettings: {
                    organizationName: {
                        name: "название организации",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    legalAddress: {
                        name: "юридический адрес",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    fieldActivity: {
                        name: "вид деятельности",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                },
                divisionSettings: {
                    divisionName: {
                        name: "название подразделения или филиала",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    physicalAddress: {
                        name: "физический адрес",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    description: {
                        name: "примечание",
                        value: "",
                    },
                },
                sourceSettings: {
                    sourceID: {
                        name: "цифровой идентификатор",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },                    
                    shortName: {
                        name: "краткое название источника",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    ipAddress: {
                        name: "ip адрес",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    port: {
                        name: "сетевой порт",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    architecture: {
                        name: "архитектура",
                        value: "client",
                    },
                    maxSimultaneousProc: {
                        name: "параллельные задачи фильтрации",
                        value: 5,
                    },
                    networkChannel: {
                        name: "тип сетевого канала",
                        value: "ip",
                    },
                    token: {
                        name: "идентификационный токен",
                        value: helpers.tokenRand(),
                    },
                    telemetry: {
                        name: "телеметрия",
                        value: false,
                    },
                    directoriesNetworkTraffic: {
                        name: "директории с файлами",
                        isValid: false,
                        isInvalid: false,
                        value: [],
                    },
                    description: {
                        name: "примечание",
                        value: "",
                    },
                    newFolder: "",
                },
            },
        };

        this.buttonAdd = this.buttonAdd.bind(this);
        this.windowClose = this.windowClose.bind(this); 
        this.handlerInput = this.handlerInput.bind(this);
        this.handlerNewFolder = this.handlerNewFolder.bind(this);
        this.handelerFolderDelete = this.handelerFolderDelete.bind(this);

        this.sourcesInput = this.sourcesInput.bind(this);
        this.divisionInput = this.divisionInput.bind(this);
        this.organizationInput =  this.organizationInput.bind(this);
    }

    windowClose(){

        console.log(`закрыть модальное окно для типа ${JSON.stringify(this.props.settings.type)}`);

        let pattern = {
            "organization": "organizationSettings",
            "division": "divisionSettings",
            "source": "sourceSettings",
        };

        //очищаем всю информацию из состояния
        let modalBodySettings = this.state.modalBodySettings;
        for(let name in modalBodySettings[pattern[this.props.settings.type]]){
            for(let key in modalBodySettings[pattern[this.props.settings.type]][name]){              
                if(key === "isValid" || key === "isInvalid"){
                    modalBodySettings[pattern[this.props.settings.type]][name][key] = false;
                } else if(name === "directoriesNetworkTraffic" && key === "value"){
                    modalBodySettings[pattern[this.props.settings.type]][name][key] = [];
                } else {
                    modalBodySettings[pattern[this.props.settings.type]][name][key] = "";
                }
            }
        }

        modalBodySettings.sourceSettings.token.value = helpers.tokenRand();

        this.setState({ alertMessage: "" });
        this.setState({ alertMessageShow: false });
        this.setState({ modalBodySettings: modalBodySettings });

        this.props.onHide();
    }

    buttonAdd(){
        console.log(`Получить и проверить входные параметры заданные пользователем для модального окна типа: '${this.props.settings.type}'`);

        /**
         * проверяем корректность значений и их наличие
         */
        let valueIsEmpty = false;       
        let settings = this.state.modalBodySettings;
        let listElem = [ 
            "sourceID",
            "shortName",
            "ipAddress",
            "port" 
        ];

        let objUpdate = Object.assign({}, this.state);        

        switch(this.props.settings.type){
        case "organization":
            for(let name in settings.organizationSettings){               
                if((settings.organizationSettings[name].value).length === 0){
                    valueIsEmpty = true;

                    objUpdate.modalBodySettings.organizationSettings[name].isValid = false;
                    objUpdate.modalBodySettings.organizationSettings[name].isInvalid = true;
                }
            }

            if(valueIsEmpty){
                this.setState( objUpdate );
                
                return;
            }

            this.props.handlerAddButton({
                windowType: this.props.settings.type,
                options: {
                    id: helpers.tokenRand(),
                    organizationName: objUpdate.modalBodySettings.organizationSettings.organizationName.value,
                    legalAddress: objUpdate.modalBodySettings.organizationSettings.legalAddress.value,
                    fieldActivity: objUpdate.modalBodySettings.organizationSettings.fieldActivity.value,
                },
            });

            for(let name in settings.organizationSettings){
                objUpdate.modalBodySettings.organizationSettings[name].value = "";

                objUpdate.modalBodySettings.organizationSettings[name].isValid = false;
                objUpdate.modalBodySettings.organizationSettings[name].isInvalid = false;
            }

            this.setState( objUpdate );

            break;

        case "division":
            for(let name in settings.divisionSettings){
                if(name === "description"){
                    continue;
                }

                if((settings.divisionSettings[name].value).length === 0){
                    valueIsEmpty = true;

                    objUpdate.modalBodySettings.divisionSettings[name].isValid = false;
                    objUpdate.modalBodySettings.divisionSettings[name].isInvalid = true;
                }
            }

            if(valueIsEmpty){
                this.setState( objUpdate );
                
                return;
            }

            this.props.handlerAddButton({
                windowType: this.props.settings.type,
                options: {
                    id: helpers.tokenRand(),
                    parentID: this.props.parentOrganizationID,
                    divisionName: objUpdate.modalBodySettings.divisionSettings.divisionName.value,
                    physicalAddress: objUpdate.modalBodySettings.divisionSettings.physicalAddress.value,
                    description: objUpdate.modalBodySettings.divisionSettings.description.value,
                },
            });

            for(let name in settings.divisionSettings){
                if(name === "description"){
                    continue;
                }

                objUpdate.modalBodySettings.divisionSettings[name].value = "";                    

                objUpdate.modalBodySettings.divisionSettings[name].isValid = false;
                objUpdate.modalBodySettings.divisionSettings[name].isInvalid = false;
            }

            this.setState( objUpdate );

            break;

        case "source":
            listElem.forEach((item) => {
                if(settings.sourceSettings[item].value.length === 0){
                    valueIsEmpty = true;

                    objUpdate.modalBodySettings.sourceSettings[item].isValid = false;
                    objUpdate.modalBodySettings.sourceSettings[item].isInvalid = true;
                }
            });

            if(settings.sourceSettings.directoriesNetworkTraffic.value.length === 0){
                valueIsEmpty = true; 

                objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.isValid = false;
                objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.isInvalid = true;
            }

            if(valueIsEmpty){
                this.setState( objUpdate );
                
                return;
            }

            this.props.handlerAddButton({
                windowType: this.props.settings.type,
                options: {
                    id: helpers.tokenRand(),                   
                    parentID: this.props.parentDivisionID,
                    sourceID: objUpdate.modalBodySettings.sourceSettings.sourceID.value,                    
                    shortName: objUpdate.modalBodySettings.sourceSettings.shortName.value,
                    ipAddress: objUpdate.modalBodySettings.sourceSettings.ipAddress.value,
                    port: objUpdate.modalBodySettings.sourceSettings.port.value,
                    architecture: objUpdate.modalBodySettings.sourceSettings.architecture.value,
                    maxSimultaneousProc: objUpdate.modalBodySettings.sourceSettings.maxSimultaneousProc.value,
                    networkChannel: objUpdate.modalBodySettings.sourceSettings.networkChannel.value,
                    token: objUpdate.modalBodySettings.sourceSettings.token.value,
                    telemetry: objUpdate.modalBodySettings.sourceSettings.telemetry.value,
                    directoriesNetworkTraffic: objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.value,
                    description: objUpdate.modalBodySettings.sourceSettings.description.value,
                },
            });

            listElem.forEach((item) => {
                objUpdate.modalBodySettings.sourceSettings[item].value = "";

                objUpdate.modalBodySettings.sourceSettings[item].isValid = false;
                objUpdate.modalBodySettings.sourceSettings[item].isInvalid = false;
            });
            objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.value = [];
            objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.isValid = false;
            objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.isInvalid = false;

            this.setState( objUpdate );

        }

        this.props.onHide();
    }

    handlerInput(typeInput, event){
        const value = event.target.value;
        const elementName = event.target.id;

        if(typeInput === "organization"){
            this.organizationInput(elementName, value);
        }
        if(typeInput === "division"){
            this.divisionInput(elementName, value);
        }
        if(typeInput === "source"){
            this.sourcesInput(elementName, value);
        }
    }

    handlerNewFolder(){
        let newFolder = this.state.modalBodySettings.sourceSettings.newFolder.trim();
        let dirNetTraff = this.state.modalBodySettings.sourceSettings.directoriesNetworkTraffic;
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

        objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.value.push(newFolder);
        objUpdate.modalBodySettings.sourceSettings.newFolder = "";
        objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.isValid = false;
        objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.isInvalid = false;

        this.setState( objUpdate );

        document.getElementById("input_folder").value = "";
    }

    handelerFolderDelete(nameFolder){
        let objUpdate = Object.assign({}, this.state);        
        let list = objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.value;
        objUpdate.modalBodySettings.sourceSettings.directoriesNetworkTraffic.value = list.filter((item) => (item !== nameFolder));

        this.setState( objUpdate );
    }

    organizationInput(elementName, value){     
        let objUpdate = Object.assign({}, this.state);

        switch(elementName){
        case "organization_name":
            objUpdate.modalBodySettings.organizationSettings.organizationName.value = value;

            if(!helpers.checkInputValidation({
                "name": "fullNameHost", 
                "value": value, 
            })){
                objUpdate.modalBodySettings.organizationSettings.organizationName.isInvalid = true;
                objUpdate.modalBodySettings.organizationSettings.organizationName.isValid = false;
            } else {
                objUpdate.modalBodySettings.organizationSettings.organizationName.isInvalid = false;
                objUpdate.modalBodySettings.organizationSettings.organizationName.isValid = true;
            }

            break;

        case "legal_address":
            objUpdate.modalBodySettings.organizationSettings.legalAddress.value = value;

            if(!helpers.checkInputValidation({
                "name": "stringRuNumCharacter", 
                "value": value, 
            })){
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isInvalid = true;
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isValid = false;
            } else {
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isInvalid = false;
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isValid = true;
            }
            
            break;

        case "organization_field_selector":
            objUpdate.modalBodySettings.organizationSettings.fieldActivity.value = value;
            objUpdate.modalBodySettings.organizationSettings.fieldActivity.isInvalid = false;
            objUpdate.modalBodySettings.organizationSettings.fieldActivity.isValid = true;
        }

        this.setState( objUpdate );
    }

    divisionInput(elementName, value){
        let objUpdate = Object.assign({}, this.state);

        switch(elementName){
        case "division_name":
            objUpdate.modalBodySettings.divisionSettings.divisionName.value = value;

            if(!helpers.checkInputValidation({
                "name": "stringRuNumCharacter", 
                "value": value, 
            })){
                objUpdate.modalBodySettings.divisionSettings.divisionName.isInvalid = true;
                objUpdate.modalBodySettings.divisionSettings.divisionName.isValid = false;
            } else {
                objUpdate.modalBodySettings.divisionSettings.divisionName.isInvalid = false;
                objUpdate.modalBodySettings.divisionSettings.divisionName.isValid = true;
            }

            break;

        case "division_physical_address":
            objUpdate.modalBodySettings.divisionSettings.physicalAddress.value = value;

            if(!helpers.checkInputValidation({
                "name": "stringRuNumCharacter", 
                "value": value, 
            })){
                objUpdate.modalBodySettings.divisionSettings.physicalAddress.isInvalid = true;
                objUpdate.modalBodySettings.divisionSettings.physicalAddress.isValid = false;
            } else {
                objUpdate.modalBodySettings.divisionSettings.physicalAddress.isInvalid = false;
                objUpdate.modalBodySettings.divisionSettings.physicalAddress.isValid = true;
            }
            
            break;

        case "division_description":
            objUpdate.modalBodySettings.divisionSettings.description.value = value;

        }

        this.setState( objUpdate );
    }

    sourcesInput(elementName, value){
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
            objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].value = value;    
            this.setState( objUpdate );
    
            return;
        }
        
        if(!helpers.checkInputValidation({name: listElem[elementName].pattern, value: value })){
            objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].isValid = false;
            objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].isInvalid = true;
        } else {
            if(elementName === "input_folder"){
                objUpdate.modalBodySettings.sourceSettings.newFolder = value;        
            } else {
                objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].value = value;
            }

            objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].isValid = true;
            objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].isInvalid = false;
        }

        this.setState( objUpdate );
    }

    render(){
        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg">
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Добавить {this.props.settings.name}</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <CreateModalBody 
                        handlerInput={this.handlerInput}
                        addNewFolder={this.handlerNewFolder}
                        storageInput={this.state.modalBodySettings}
                        typeModalBody={this.props.settings.type}
                        listFieldActivity={this.props.settings.listFieldActivity} 
                        handelerFolderDelete={this.handelerFolderDelete} />
                </Modal.Body>
                <Modal.Footer>
                    <Button onClick={this.windowClose} variant="outline-secondary">закрыть</Button>
                    <Button onClick={this.buttonAdd} variant="outline-primary">добавить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowAddEntity.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
    settings: PropTypes.object,
    parentDivisionID: PropTypes.string,
    parentOrganizationID: PropTypes.string,
    handlerAddButton: PropTypes.func,
};