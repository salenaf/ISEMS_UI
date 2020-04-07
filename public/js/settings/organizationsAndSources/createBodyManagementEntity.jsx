import React from "react";
import { Accordion, Button, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import { ModalWindowConfirmMessage } from "../../modalwindows/modalWindowConfirmMessage.jsx";
import { helpers } from "../../common_helpers/helpers.js";

class ShowEntityInformation extends React.Component {
    constructor(props){
        super(props);

        this.showInformation = this.showInformation.bind(this);
        this.createDivisionCard = this.createDivisionCard.bind(this);
    }

    handlerSaveButton(type, id){
        this.props.handlerSave(type, id);
    }

    handlerDeleteButton(type, id){
        this.props.handlerDelete(type, id);
    }

    createDivisionCard(){
        let num = 1;

        if(this.props.resivedInfo.listDivision.length === 0){
            return (<React.Fragment></React.Fragment>);
        }

        this.props.resivedInfo.listDivision.sort((a, b) => {
            if(a.divisionName > b.divisionName) return 1;
            if(a.divisionName === b.divisionName) return 0;
            if(a.divisionName < b.divisionName) return -1;
        });

        return this.props.resivedInfo.listDivision.map((item) => {
            item.listSource.sort((a, b) => {
                if(a.source_id > b.source_id) return 1;
                if(a.source_id === b.source_id) return 0;
                if(a.source_id < b.source_id) return -1;
            });

            return (
                <Card border="dark" key={`key_division_${num}`}>
                    <Accordion.Toggle className="p-2 alert-secondary text-dark" as={Card.Header} eventKey={num}>{item.divisionName}</Accordion.Toggle>
                    <Accordion.Collapse eventKey={num++}>
                        <Card.Body>
                            <Row>
                                <Col>
                                    <Form.Control 
                                        type="text" 
                                        onChange={this.props.handlerInputChange} 
                                        value={item.divisionName} 
                                        isValid={item.divisionNameIsValid}
                                        isInvalid={item.divisionNameIsInvalid}
                                        id={`division_name:${item.id}`} />
                                </Col>
                                <Col>
                                    <Form.Control 
                                        as="textarea" 
                                        onChange={this.props.handlerInputChange} 
                                        value={item.physicalAddress} 
                                        isValid={item.physicalAddressIsValid}
                                        isInvalid={item.physicalAddressIsInvalid}
                                        id={`physical_address:${item.id}`} />
                                </Col>
                            </Row>
                            <Row>
                                <Col md={6}><Form.Control as="textarea" onChange={this.props.handlerInputChange} value={item.description} id={`description:${item.id}`}></Form.Control></Col>
                                <Col md={2} className="text-left">источники:</Col>
                                <Col md={4} className="text-left"><ul>{item.listSource.map((item) => <li key={`li_source_${item.source_id}_${item.short_name}`}>{`${item.source_id} ${item.short_name}`}</li>)}</ul></Col>
                            </Row>
                            <Row>
                                <Col className="text-right">
                                    <Button variant="outline-success" onClick={this.handlerSaveButton.bind(this, "division", item.id)} size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" onClick={this.handlerDeleteButton.bind(this, "division", item.id)} size="sm">удалить</Button>
                                </Col>
                            </Row>
                        </Card.Body>
                    </Accordion.Collapse>
                </Card>
            );
        });
    }

    showInformation(){
        if(!this.props.showInfo){
            return;
        }
 
        let list = this.props.listFieldActivity;

        let num = 1;

        return (
            <Accordion defaultActiveKey="0" style={{ width: "55rem" }}>
                <Card border="info">
                    <Accordion.Toggle className="p-3 alert-primary text-dark" as={Card.Header} eventKey="0">{this.props.resivedInfo.organizationName}</Accordion.Toggle>
                    <Accordion.Collapse eventKey="0">
                        <Card.Body>
                            <Row>
                                <Col><Form.Control 
                                    type="text" 
                                    onChange={this.props.handlerInputChange} 
                                    value={this.props.resivedInfo.organizationName} 
                                    isValid={this.props.resivedInfo.organizationNameIsValid}
                                    isInvalid={this.props.resivedInfo.organizationNameIsInvalid}
                                    id="organization_name" />
                                </Col>
                                <Col>
                                    <Form.Control 
                                        as="textarea" 
                                        onChange={this.props.handlerInputChange} 
                                        value={this.props.resivedInfo.legalAddress}
                                        isValid={this.props.resivedInfo.legalAddressIsValid} 
                                        isInvalid={this.props.resivedInfo.legalAddressIsInvalid} 
                                        id="legal_address" />
                                </Col>
                            </Row>
                            <Row>
                                <Col>
                                    <Form.Control as="select" onChange={this.props.handlerInputChange} value={this.props.resivedInfo.fieldActivity} id="field_activity" size="sm">
                                        {list.map((item) => <option value={item} key={`list_field_activity_${num++}`}>{item}</option>)}
                                    </Form.Control>
                                </Col>
                                <Col></Col>
                            </Row>
                            <Row>
                                <Col className="text-right">
                                    <Button variant="outline-success" onClick={this.handlerSaveButton.bind(this, "organization", this.props.resivedInfo.id)} size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" onClick={this.handlerDeleteButton.bind(this, "organization", this.props.resivedInfo.id)} size="sm">удалить</Button>
                                </Col>
                            </Row>
                        </Card.Body>
                    </Accordion.Collapse>
                </Card>
                {this.createDivisionCard()}
            </Accordion>
        );
    }

    render(){
        return <Row><Col md={{ span: 9, offset: 1 }}>{this.showInformation()}</Col></Row>;
    }
}

ShowEntityInformation.propTypes = {
    showInfo: PropTypes.bool.isRequired,
    handlerSave: PropTypes.func.isRequired,
    handlerDelete: PropTypes.func.isRequired,
    resivedInfo: PropTypes.object.isRequired,
    listFieldActivity: PropTypes.array.isRequired,
    handlerInputChange: PropTypes.func.isRequired,
};

class CreateListEntity extends React.Component {
    constructor(props){
        super(props);

        this.listSource = this.listSource.bind(this);
        this.listDivision = this.listDivision.bind(this);
        this.listOrganization = this.listOrganization.bind(this);

        this.handlerChoose = this.handlerChoose.bind(this);
    }

    componentDidMount() {
        this.el = $("#dropdown_all_entity");
       
        this.el.select2({
            placeholder: "выбор сущности",
            containerCssClass: "input-group input-group-sm",
        });
    
        this.el.on("change", this.handlerChoose);
    }

    listOrganization(){
        let arrayTmp = Object.keys(this.props.listOrganization).sort().map((name) => {
            return <option key={`key_org_${this.props.listOrganization[name]}`} value={`organization:${this.props.listOrganization[name]}`}>{name}</option>;
        });

        return arrayTmp;
    }

    listDivision(){       
        let arrayTmp = Object.keys(this.props.listDivision).sort().map((name) => {
            return <option key={`key_divi_${this.props.listDivision[name].did}`} value={`division:${this.props.listDivision[name].did}`}>{name}</option>;
        });

        return arrayTmp;
    }

    listSource(){
        let arrayTmp = Object.keys(this.props.listSource).sort((a, b) => a < b).map((name) => {
            return <option key={`key_sour_${this.props.listSource[name].sid}`} value={`source:${this.props.listSource[name].sid}`}>{name}</option>;
        });

        return arrayTmp;
    }

    handlerChoose(e){
        if(typeof e.target === "undefined"){
            return;
        }

        if(typeof e.target.value === "undefined"){
            return;
        }

        let [ typeValue, valueID ] = e.target.value.split(":");

        /** 
         * В Production отправляем, через WebSocket, серверу запрос на поиск информации в БД
         * при этом в конструкторе должна быть выполненна функция с обработчиком сообщений 
         * от сервера
         */

        /* для макета следующая реализация */
        this.props.handlerSelected({
            type: typeValue,
            value: valueID,
        });
    }

    render(){
        return (
            <select id="dropdown_all_entity">
                <option></option>
                <optgroup label="организации">
                    {this.listOrganization()}
                </optgroup>
                <optgroup label="подразделения или филиалы">
                    {this.listDivision()}
                </optgroup>
                <optgroup label="источники">
                    {this.listSource()}
                </optgroup>
            </select>
        );
    }
}

CreateListEntity.propTypes = {
    listOrganization: PropTypes.object.isRequired,
    listDivision: PropTypes.object.isRequired,
    listSource: PropTypes.object.isRequired,
    handlerSelected: PropTypes.func.isRequired,
};


export default class CreateBodyManagementEntity extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showInfo: false,
            modalWindowSourceDel: false,
            listOrganizationName: this.createListOrganization.call(this, this.props.listShortEntity.shortListOrganization),
            listDivisionName: this.createListDivision.call(this, this.props.listShortEntity.shortListDivision),
            objectShowedInformation: {},
        };

        this.deleteEntityOptions = {};

        this.handlerEvents.call(this);
        this.listSourceName = this.createListSource.call(this, this.props.listShortEntity);

        this.checkValue = this.checkValue.bind(this);
        this.handlerSave = this.handlerSave.bind(this);
        this.handlerDelete = this.handlerDelete.bind(this);
        this.handlerSelected = this.handlerSelected.bind(this);
        this.handlerInputChange = this.handlerInputChange.bind(this);
        this.handlerEntityDelete = this.handlerEntityDelete.bind(this);
        this.closeModalWindowSourceDel = this.closeModalWindowSourceDel.bind(this);
        this.searchEntityInObjectShowedInformation = this.searchEntityInObjectShowedInformation.bind(this);
    }

    handlerEvents(){

        console.log("func 'handlerEvents'");

        this.props.socketIo.on("entity: set info about organization and division", (data) => {
            console.log("Events 'entity: set info about organization and division'");
            console.log(data);

            this.setState({ objectShowedInformation: data.arguments });
            this.setState({ showInfo: true });
        });
    }

    createListOrganization(list){
        let listTmp = {};
        list.forEach((item) => {
            listTmp[item.name] = item.id;
        });

        return listTmp;
    }

    createListDivision(list){
        let listTmp = {};
        list.forEach((item) => {
            listTmp[item.name] = {
                did: item.id,
                oid: item.id_organization,
            };
        });

        return listTmp;
    }

    createListSource(list){
        let listTmp = {};
        list.shortListSource.forEach((item) => {
            let organizationId = "";
            for(let d of list.shortListDivision){
                if(d.id === item.id_division){
                    organizationId = d.id_organization;

                    break;
                }
            }

            listTmp[item.short_name] = {
                sid: item.id,
                did: item.id_division,
                oid: organizationId,
            };
        });

        return listTmp;
    }

    searchEntityInObjectShowedInformation(type, id){
        let osi = this.state.objectShowedInformation;

        if(type === "organization"){
            if(osi.id === id){
                return osi;
            }

            return {};
        }

        for(let i = 0; i < osi.listDivision.length; i++){
            if(osi.listDivision[i].id === id){
                return osi.listDivision[i];
            }
        }

        return {};
    }

    handlerSelected(obj){
        this.props.socketIo.emit("entity information", { 
            actionType: "get info about organization or division",
            arguments: obj
        });
    }

    handlerInputChange(e){
        let pattern = {
            "organization_name": "organizationName",
            "division_name": "divisionName",
            "legal_address": "legalAddress",
            "field_activity": "fieldActivity",
            "physical_address": "physicalAddress",
            "description": "description",
        };
        let tmpObj = this.state.objectShowedInformation;

        let [ name, ID ] = e.target.id.split(":");
        if(typeof ID === "undefined"){
            tmpObj[pattern[name]] = e.target.value;

            if(this.checkValue(pattern[name], e.target.value)){
                tmpObj[`${pattern[name]}IsValid`] = true;
                tmpObj[`${pattern[name]}IsInvalid`] = false;
            } else {
                tmpObj[`${pattern[name]}IsValid`] = false;
                tmpObj[`${pattern[name]}IsInvalid`] = true;
            }
        } else {
            for(let i = 0; i < tmpObj.listDivision.length; i++){
                if(tmpObj.listDivision[i].id === ID){
                    tmpObj.listDivision[i][pattern[name]] = e.target.value;

                    if(this.checkValue(pattern[name], e.target.value)){
                        tmpObj.listDivision[i][`${pattern[name]}IsValid`] = true;
                        tmpObj.listDivision[i][`${pattern[name]}IsInvalid`] = false;
                    } else {
                        tmpObj.listDivision[i][`${pattern[name]}IsValid`] = false;
                        tmpObj.listDivision[i][`${pattern[name]}IsInvalid`] = true;
                    }

                    break;
                }
            }
        }

        this.setState({ objectShowedInformation: tmpObj });
    }

    handlerSave(entityType, entityID){
        console.log("func 'handlerSave', START...");

        let entityInfo = this.searchEntityInObjectShowedInformation(entityType, entityID);

        if(entityType === "organization"){

            //проверяем что бы поля были валидны
            if(entityInfo.organizationNameIsInvalid || entityInfo.legalAddressIsInvalid){
                return;
            }

            this.props.socketIo.emit("change organization info", {
                actionType: "change",
                entityId: entityID,
                arguments: {
                    organizationName: entityInfo.organizationName,
                    fieldActivity: entityInfo.fieldActivity,
                    legalAddress: entityInfo.legalAddress,
                }
            });

            return;
        } 

        //проверяем что бы поля были валидны
        if(entityInfo.divisionNameIsInvalid || entityInfo.physicalAddressIsInvalid){
            return;
        }

        this.props.socketIo.emit("change division info", {
            actionType: "change",
            entityId: entityID,
            arguments: {
                divisionName: entityInfo.divisionName,
                physicalAddress: entityInfo.physicalAddress,
                description: entityInfo.description,
            }
        });
    }

    handlerDelete(entityType, entityID){
        let entityInfo = this.searchEntityInObjectShowedInformation(entityType, entityID);

        let entityName = (entityType === "organization")? entityInfo.organizationName: entityInfo.divisionName;
        this.deleteEntityOptions = {
            entityType: entityType,
            entityID: entityID,
            name: entityName,
        };

        this.setState({ modalWindowSourceDel: true });
    }

    handlerEntityDelete(){
        let request = JSON.stringify({ action: "entity_delete", entityType: this.deleteEntityOptions.entityType, entityID: this.deleteEntityOptions.entityID });

        /**
         * В БД сделать проверку на наличие дочерних потомков у удаляемой сущности. Если есть потомки то удаление не производится,
         * выводится информационное сообщение о невозможности удалить сущност у которой есть потомки
         */

        console.log(`отправляем серверу запрос для 'УДАЛЕНИЯ' информации из БД, ${request}`);
        
        this.closeModalWindowSourceDel();
    }

    closeModalWindowSourceDel(){
        this.setState({ modalWindowSourceDel: false });
    }

    checkValue(nameInput, value){
        let elemName = {
            "organizationName": "fullNameHost",
            "legalAddress": "stringRuNumCharacter",
            "divisionName": "stringRuNumCharacter",
            "physicalAddress": "stringRuNumCharacter",
        };

        if(typeof elemName[nameInput] === "undefined") {
            return false;
        }

        return helpers.checkInputValidation({
            "name": elemName[nameInput], 
            "value": value, 
        });
    }

    render(){
        let numOrganization = Object.keys(this.state.listOrganizationName).length;
        let numDivision = Object.keys(this.state.listDivisionName).length;
        let numSource = Object.keys(this.listSourceName).length;

        return (
            <React.Fragment>
                <br/>
                <Row>
                    <Col className="text-left">Всего, организаций: {numOrganization}, подразделений: {numDivision}, источников: {numSource}.</Col>
                </Row>
                <Row>
                    <Col className="text-left">
                        <CreateListEntity 
                            listOrganization={this.state.listOrganizationName}
                            listDivision={this.state.listDivisionName}
                            listSource={this.listSourceName}

                            handlerSelected={this.handlerSelected} />
                    </Col>
                </Row>
                <br/>
                <ShowEntityInformation 
                    showInfo={this.state.showInfo}
                    handlerSave={this.handlerSave}
                    handlerDelete={this.handlerDelete}
                    listFieldActivity={this.props.listFieldActivity} 
                    resivedInfo={this.state.objectShowedInformation}
                    handlerInputChange={this.handlerInputChange} />
                <ModalWindowConfirmMessage 
                    show={this.state.modalWindowSourceDel}
                    onHide={this.closeModalWindowSourceDel}
                    msgBody={`Вы действительно хотите удалить ${(this.deleteEntityOptions.entityType === "organization") ? "организацию":"подразделение"} '${this.deleteEntityOptions.name}'`}
                    msgTitle={"Удаление"}
                    nameDel=""
                    handlerConfirm={this.handlerEntityDelete}
                />
            </React.Fragment>
        );
    }
}

CreateBodyManagementEntity.propTypes ={
    socketIo: PropTypes.object.isRequired,
    listShortEntity: PropTypes.object.isRequired,
    listFieldActivity: PropTypes.array.isRequired,
};

