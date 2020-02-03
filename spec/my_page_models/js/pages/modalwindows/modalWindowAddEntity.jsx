import React from "react";
import { Button, Col, Form, FormControl, Row, Modal, InputGroup } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "../../common_helpers/helpers.js";
import { ModalAlertDangerMessage } from "../../common/modalAlertMessage.jsx";

class ListFolder extends React.Component {
    constructor(props){
        super(props);

        this.listFolders = this.listFolders.bind(this);        
    }

    deleteNewFolder(folderName){
        this.props.handelerFolderDelete(folderName);
    }

    listFolders(){
        return this.props.directoriesNetworkTraffic.map(item => {
            return <li key={`new_folder_${item}`}>
                {item}&nbsp;
                <button onClick={this.deleteNewFolder.bind(this, item)} type="button" className="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                </button>
            </li>;
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
                    id="organization_field_selector" 
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

        this.state = {
            newFolder: "",
            isValid: false,
            isInvalid: false,
        };

        this.handlerInput = this.handlerInput.bind(this);
        this.handlerNewFolder = this.handlerNewFolder.bind(this);
    }

    handlerInput(e){
        let value = e.target.value;

        /* 
                Внимание!!!
        пока проверяем только длинну RegExp в production
        */

        /*if(value.length < 5){
            this.setState({ isValid: false });
            this.setState({ isInvalid: true });
        } else {
            this.setState({ isValid: true });
            this.setState({ isInvalid: false });
        }*/

        this.setState({ newFolder: value });

        this.props.handlerInput.call(e, "source");
    }

    handlerNewFolder(){

        //        let nf = this.state.newFolder;

        //        this.setState({ newFolder: "" });
        //this.setState({ isValid: false });
        //this.setState({ isInvalid: false });

        //очищаем поле ввода
        document.getElementById("input_folder").value = "";

        this.props.addNewFolder(this.state.newFolder);
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
                        <Form.Control id="source_architecture" as="select" defaultValue="client">
                            <option value="client">клиент</option>
                            <option value="server">сервер</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col}>
                        <Form.Label>Параллельные задачи фильтрации</Form.Label>
                        <Form.Control id="source_max_simultaneous_proc" as="select" defaultValue="5">
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
                    <Form.Group as={Col}>
                        <Form.Label>Тип сетевого канала</Form.Label>
                        <Form.Control id="source_network_channel" as="select" defaultValue="ip">
                            <option value="ip">ip/vlan</option>
                            <option value="pppoe">pppoe</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col}>
                        <Form.Label>Идентификационный токен</Form.Label>
                        <Form.Control id="source_token" type="text" readOnly defaultValue={helpers.tokenRand()} />
                    </Form.Group>
                </Form.Row>
                <Row>
                    <Col lg={4}>
                        <Form.Check 
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
                    <Form.Control id="source_description" as="textarea" rows="3" />
                </Form.Group>
            </Form>
        );
    }
}
/**
 *                                 onChange={this.handlerInput}
 * 
 *                                 isValid={this.state.isValid}
                                isInvalid={this.state.isInvalid}
                                  isValid={this.props.storageInput.directoriesNetworkTraffic.isValid}
                    isInvalid={this.props.storageInput.directoriesNetworkTraffic.isInvalid}
 */
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
            alertMessage: "",
            alertMessageShow: false,
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
                        value: "",
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

        this.alertShow = this.alertShow.bind(this);
        this.alertClose = this.alertClose.bind(this);
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
                } else {
                    modalBodySettings[pattern[this.props.settings.type]][name][key] = "";
                }
            }
        }
        this.setState({ alertMessage: "" });
        this.setState({ alertMessageShow: false });
        this.setState({ modalBodySettings: modalBodySettings });

        this.props.onHide();
    }

    alertShow(){
        this.setState({ alertMessageShow: true });
    }

    alertClose(){
        this.setState({ alertMessageShow: false });
    }

    buttonAdd(){
        console.log(`Получить и проверить входные параметры заданные пользователем для модального окна типа: '${this.props.settings.type}'`);

        /**
         * проверяем корректность значений и их наличие
         */
        let patternOrganization = {
            organizationName: "isValid",
            legalAddress: "isValid",
            fieldActivity: "length",
        };
        let patternDivision = {
            divisionName: "isValid",
            physicalAddress: "isValid",
        };
        let settings = this.state.modalBodySettings;

        switch(this.props.settings.type){
        case "organization":
            for(let name in settings.organizationSettings){
                this.setState({ alertMessage: "" });
                this.setState({ alertMessageShow: false });
                
                if((settings.organizationSettings[name].value).length === 0){
                    this.setState({alertMessage: `Значение поля '${settings.organizationSettings[name].name}' не задано.`});
                    this.alertShow();

                    return;
                }

                if(patternOrganization[name] === "isValid"){
                    if(!settings.organizationSettings[name].isValid){
                        this.setState({alertMessage: `Значение поля '${settings.organizationSettings[name].name}' некорректно.`});
                        this.alertShow();

                        return;
                    }
                }
            }

            this.props.handlerAddButton({
                windowType: this.props.settings.type,
                options: {
                    id: helpers.tokenRand(),
                    organizationName: settings.organizationSettings.organizationName.value,
                    legalAddress: settings.organizationSettings.legalAddress.value,
                    fieldActivity: settings.organizationSettings.fieldActivity.value,
                },
            });

            break;

        case "division":
            for(let name in settings.divisionSettings){
                this.setState({ alertMessage: "" });
                this.setState({ alertMessageShow: false });

                if((name !== "description") && ((settings.divisionSettings[name].value).length === 0)){
                    this.setState({alertMessage: `Значение поля '${settings.divisionSettings[name].name}' не задано.`});
                    this.alertShow();

                    return;
                }

                if(patternDivision[name] === "isValid"){
                    if(!settings.divisionSettings[name].isValid){
                        this.setState({alertMessage: `Значение поля '${settings.divisionSettings[name].name}' некорректно.`});
                        this.alertShow();

                        return;
                    }
                }
            }

            this.props.handlerAddButton({
                windowType: this.props.settings.type,
                options: {
                    id: helpers.tokenRand(),
                    parentID: this.props.parentOrganizationID,
                    divisionName: settings.divisionSettings.divisionName.value,
                    physicalAddress: settings.divisionSettings.physicalAddress.value,
                    description: settings.divisionSettings.description.value,
                },
            });

            break;

        case "source":
            /**
 * parents id 
 * parentDivisionID
 * parentOrganizationID
 */

            console.log("Validation input parameters...");

            return;

        }

        this.props.onHide();
    }

    handlerInput(typeInput, event){
        console.log(typeInput);
        console.log(event);

        const value = event.target.value;
        const elementName = event.target.id;

        /*
        console.log(`value: ${value}`);
        console.log(`element name: ${elementName}`);
        console.log(`type input: ${typeInput}`);
        */

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
        let newFolder = this.state.modalBodySettings.sourceSettings.newFolder;
        if(this.state.modalBodySettings.sourceSettings.directoriesNetworkTraffic.isInvalid){
            return;
        }

        console.log("|||||||| "+newFolder+" ||||||||");

        if(newFolder[0] !== "/"){
            newFolder = "/"+newFolder;
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

        /**
        * Выполняем проверку параметров вводимых пользователем
        * для макета выполняется простая проверка на длинну
        * Для продакшена надо прикрутить RegExp
        */
       
        let objUpdate = Object.assign({}, this.state);

        /**
        * Пока проверяем только на длину
        */

        switch(elementName){
        case "organization_name":
            objUpdate.modalBodySettings.organizationSettings.organizationName.value = value;
            if(value.length < 5){
                objUpdate.modalBodySettings.organizationSettings.organizationName.isInvalid = true;
                objUpdate.modalBodySettings.organizationSettings.organizationName.isValid = false;
            } else {
                objUpdate.modalBodySettings.organizationSettings.organizationName.isInvalid = false;
                objUpdate.modalBodySettings.organizationSettings.organizationName.isValid = true;
            }

            break;

        case "legal_address":
            objUpdate.modalBodySettings.organizationSettings.legalAddress.value = value;
            if(value.length < 5){
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isInvalid = true;
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isValid = false;
            } else {
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isInvalid = false;
                objUpdate.modalBodySettings.organizationSettings.legalAddress.isValid = true;
            }
            
            break;

        case "organization_field_selector":
            objUpdate.modalBodySettings.organizationSettings.fieldActivity.value = value;

        }

        this.setState( objUpdate );
    }

    divisionInput(elementName, value){
        /**
        * Выполняем проверку параметров вводимых пользователем
        * для макета выполняется простая проверка на длинну
        * проверка поля 'Примечание'
        * Для продакшена надо прикрутить RegExp
        
        
        console.log("func 'divisionInput', START...");
        console.log(`element name: ${elementName}`);
        console.log(`value: ${value}`);
        */

        let objUpdate = Object.assign({}, this.state);

        /**
        * Пока проверяем только на длину
        */
        switch(elementName){
        case "division_name":
            objUpdate.modalBodySettings.divisionSettings.divisionName.value = value;
            if(value.length < 5){
                objUpdate.modalBodySettings.divisionSettings.divisionName.isInvalid = true;
                objUpdate.modalBodySettings.divisionSettings.divisionName.isValid = false;
            } else {
                objUpdate.modalBodySettings.divisionSettings.divisionName.isInvalid = false;
                objUpdate.modalBodySettings.divisionSettings.divisionName.isValid = true;
            }

            break;

        case "division_physical_address":
            objUpdate.modalBodySettings.divisionSettings.physicalAddress.value = value;
            if(value.length < 5){
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

        console.log("func 'this.sourcesInput'");
        console.log(`element name: ${elementName}, value: ${value}`);

        /**
         * Здесь сделать обработку параметров ввода на основе RegExp
         * пока пусть будет только по длинне
         * 
         */

        const listElem = {
            "source_id": {
                name: "sourceID",
                pattern: "",
            },
            "source_short_name": {
                name: "shortName",
                pattern: "",
            }, 
            "source_ip": {
                name: "ipAddress",
                pattern: "",
            },
            "source_port": {
                name: "port",
                pattern: "",
            }, 
            "input_folder": {
                name: "directoriesNetworkTraffic",
                pattern: "",
            }, 
        };

        let objUpdate = Object.assign({}, this.state);

        if(elementName === "input_folder"){
            objUpdate.modalBodySettings.sourceSettings.newFolder = value;        
        }

        if(value.length < 5) {
            objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].isValid = false;
            objUpdate.modalBodySettings.sourceSettings[listElem[elementName].name].isInvalid = true;
        } else {
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
                    <ModalAlertDangerMessage show={this.state.alertMessageShow} onClose={this.alertClose} message={this.state.alertMessage}>
                        Ошибка!
                    </ModalAlertDangerMessage>
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