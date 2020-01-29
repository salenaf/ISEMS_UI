import React from "react";
import { Button, Col, Form, FormControl, Modal, InputGroup } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "../../common_helpers/helpers.js";
import { ModalAlertDangerMessage } from "../../common/modalAlertMessage.jsx";

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
                    onChange={this.props.handlerInput.bind(this,"organization")} >
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
                        onChange={this.props.handlerInput.bind(this,"organization")} />
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
                        onChange={this.props.handlerInput.bind(this,"organization")} />
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
                        isInvalid={this.props.storageInput.legalAddress.isInvalid}
                        onChange={this.props.handlerInput.bind(this,"division")} />
                </Form.Group>
                <Form.Group>
                    <Form.Label>Физический адрес</Form.Label>
                    <Form.Control 
                        as="textarea" 
                        id="division_physical_address" 
                        rows="2"
                        isValid={this.props.storageInput.physicalAddress.isValid}
                        isInvalid={this.props.storageInput.legalAddress.isInvalid}
                        onChange={this.props.handlerInput.bind(this,"division")} />
                </Form.Group>
                <Form.Group>
                    <Form.Label>Примечание</Form.Label>
                    <Form.Control 
                        as="textarea" 
                        id="division_description" 
                        rows="3"
                        onChange={this.props.handlerInput.bind(this,"division")} />
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
            <Form>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Источник</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl placeholder="цифровой идентификатор"/>
                    <FormControl placeholder="краткое название (анг. алфавит)"/>
                </InputGroup>
                <InputGroup className="mb-3">
                    <InputGroup.Prepend>
                        <InputGroup.Text>Сетевые настройки</InputGroup.Text>
                    </InputGroup.Prepend>
                    <FormControl placeholder="ip адрес"/>
                    <FormControl placeholder="сетевой порт"/>
                </InputGroup>
                <Form.Row>
                    <Form.Group as={Col} controlId="formGridState">
                        <Form.Label>Архитектура</Form.Label>
                        <Form.Control as="select" defaultValue="client">
                            <option value="client">клиент</option>
                            <option value="server">сервер</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridState">
                        <Form.Label>Параллельные задачи фильтрации</Form.Label>
                        <Form.Control as="select" defaultValue="5">
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
                    <Form.Group as={Col} controlId="formGridState">
                        <Form.Label>Тип сетевого канала</Form.Label>
                        <Form.Control as="select" defaultValue="ip">
                            <option value="ip">ip/vlan</option>
                            <option value="pppoe">pppoe</option>
                        </Form.Control>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGroupEmail">
                        <Form.Label>Идентификационный токен</Form.Label>
                        <Form.Control type="text" readOnly defaultValue={helpers.tokenRand()} />
                    </Form.Group>
                </Form.Row>
                <Form.Check 
                    type="switch"
                    id="custom-switch"
                    label="телеметрия"
                />
                <Form.Group>
                    <Form.Label>Примечание</Form.Label>
                    <Form.Control as="textarea" rows="3" />
                </Form.Group>
            </Form>
        );
    }
}

CreateBodySource.propTypes = {

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
            return <CreateBodySource />;

        default: 
            return;
        }
    }
}

CreateModalBody.propTypes = {
    handlerInput: PropTypes.func.isRequired,
    storageInput: PropTypes.object.isRequired,
    typeModalBody: PropTypes.string,
    listFieldActivity: PropTypes.object.isRequired,
};

export default class ModalWindowAddEntity extends React.Component {
    constructor(props){
        super(props);

        this.objState = {
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
                        name: "Название подразделения или филиала",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    physicalAddress: {
                        name: "Физический адрес",
                        value: "",
                        isValid: false,
                        isInvalid: false,
                    },
                    description: {
                        name: "Примечание",
                        value: "",
                    },
                },
                sourceSettings: {

                },
            },
        };

        this.state = this.objState;

        this.alertShow = this.alertShow.bind(this);
        this.alertClose = this.alertClose.bind(this);
        this.buttonAdd = this.buttonAdd.bind(this);
        this.windowClose = this.windowClose.bind(this); 
        this.handlerInput = this.handlerInput.bind(this);

        this.divisionInput = this.divisionInput.bind(this);
        this.organizationInput =  this.organizationInput.bind(this);
    }

    windowClose(){

        console.log(`закрыть модальное окно для типа ${JSON.stringify(this.props.settings.type)}`);

        //очищаем всю информацию из состояния
        this.setState(this.objState);

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
            fieldActivity: "length"
        };
        let settings = this.state.modalBodySettings;

        switch(this.props.settings.type){
        case "organization":
            for(let name in settings.organizationSettings){
                this.setState({ alertMessage: "" });
                this.setState({ alertMessageShow: false });
                
                if((settings.organizationSettings[name].value).length === 0){
                    this.setState({alertMessage: `Значение поля ${settings.organizationSettings[name].name} не задано.`});
                    this.alertShow();

                    return;
                }

                if(patternOrganization[name] === "isValid"){
                    if(!settings.organizationSettings[name].isValid){
                        this.setState({alertMessage: `Значение поля ${settings.organizationSettings[name].name} некорректно.`});
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

            break;

        case "source":


        }

        this.props.onHide();
    }

    handlerInput(typeInput, event){
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
            console.log("func 'handlerInput', SOURCE");
        }
    }

    organizationInput(elementName, value){

        /**
        * Выполняем проверку параметров вводимых пользователем
        * для макета выполняется простая проверка на длинну
        * Для продакшена надо прикрутить RegExp
        */
       
        let objUpdate = Object.assign({}, this.state);

        switch(elementName){
        case "organization_name":
            /**
            * Пока проверяем только на длину
            */
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
            /**
            * Пока проверяем только на длину
            */
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
        console.log("func 'divisionInput', START...");
        console.log(`element name: ${elementName}`);
        console.log(`value: ${value}`);
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
                        storageInput={this.state.modalBodySettings}
                        typeModalBody={this.props.settings.type}
                        listFieldActivity={this.props.settings.listFieldActivity} />
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
    handlerAddButton: PropTypes.func,
};