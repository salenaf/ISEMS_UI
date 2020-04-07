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

    handlerDropDown(){
        this.el = $("#dropdown_all_entity");
       
        this.el.select2({
            placeholder: "выбор сущности",
            containerCssClass: "input-group input-group-sm",
            width: "auto",
        });

        this.el.on("change", this.handlerChoose);
    }

    componentDidMount() {
        this.handlerDropDown.call(this);
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
            showModalAlert: false,
            modalWindowSourceDel: false,
            listOrganizationName: this.createListOrganization.call(this, this.props.listShortEntity.shortListOrganization),
            listDivisionName: this.createListDivision.call(this, this.props.listShortEntity.shortListDivision),
            objectShowedInformation: {},
        };

        this.alertMessage = { header: "", msg: "" };

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
            this.setState({ objectShowedInformation: data.arguments });
            this.setState({ showInfo: true });
        });

        this.props.socketIo.on("entity: change organization", (data) => {
            if(data.arguments.id === this.state.objectShowedInformation.id){
                let orgList = this.state.listOrganizationName;
                for(let name in orgList){
                    if(orgList[name] === data.arguments.id){
                        delete orgList[name];
   
                        orgList[this.state.objectShowedInformation.organizationName] = data.arguments.id;
                        this.setState({ listOrganizationName: orgList });

                        this.el = $("#dropdown_all_entity");
                        this.el.select2({
                            placeholder: "выбор сущности",
                            containerCssClass: "input-group input-group-sm",
                            width: "auto",
                        });

                        break;
                    }
                }
            }
        });

        this.props.socketIo.on("entity: change division", (data) => {
            let ld = this.state.objectShowedInformation.listDivision;
            if(typeof ld !== "undefined"){
                for(let i = 0; i < ld.length; i++){
                    if(ld[i].id === data.arguments.id){
                        let divList = this.state.listDivisionName;
   
                        for(let name in divList){
                            if(divList[name].did === data.arguments.id){
                                let newDivName = { did: divList[name].did, oid: divList[name].oid };

                                delete divList[name];
                                divList[ld[i].divisionName] = newDivName;
                                
                                this.setState({ listDivisionName: divList });

                                this.el = $("#dropdown_all_entity");
                                this.el.select2({
                                    placeholder: "выбор сущности",
                                    containerCssClass: "input-group input-group-sm",
                                    width: "auto",
                                });

                                break;
                            }
                        }

                        break;
                    }
                }
            }
        });

        this.props.socketIo.on("entity: delete division", (data) => {
            console.log("RECEIVED MESSAGE ABOUT DELETE DIVISION");
            console.log(data);
        });

        this.props.socketIo.on("entity: delete organization", (data) => {
            console.log("RECEIVED MESSAGE ABOUT DELETE ORGANIZTION");
            console.log(data);
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

        console.log(this.state);

        if(this.deleteEntityOptions.entityType === "organization"){
            if(this.state.objectShowedInformation.listDivision.length > 0){
                let listDivision = this.state.objectShowedInformation.listDivision.map((item) => item.divisionName).join(", ");

                this.alertMessage = { 
                    header: `Невозможно удалить организацию '${this.deleteEntityOptions.name}'.`, 
                    msg: `К данной организации принадлежат следующие дочерние подразделения: ${listDivision}. Для удаления организации сначало необходимо удалить все дочерние подразделения.` 
                };
    
                this.setState({ showModalAlert: true });

                return;
            }

            //отправляем серверу запрос на удаление 
            this.props.socketIo.emit("delete organization info", { arguments: { organizationId: this.deleteEntityOptions.entityID }});
        }

        if(this.deleteEntityOptions.entityType === "division"){
            let ld = this.state.objectShowedInformation.listDivision;
            for(let i = 0; i < ld.length; i++){
                if(ld[i].id === this.deleteEntityOptions.entityID){
                    if(ld[i].listSource.length > 0){
                        let listSource = ld[i].listSource.map((item) => `${item.source_id} ${item.short_name}`).join(", ");

                        this.alertMessage = { 
                            header: `Невозможно удалить подразделение '${ld[i].divisionName}' принадлежащее организации '${this.state.objectShowedInformation.organizationName}'.`, 
                            msg: `Данному подразделению принадлежат следующие источники: ${listSource}. Для удаления подразделения сначало необходимо удалить все дочерние источники.` 
                        };

                        this.setState({ showModalAlert: true });
                    } else {
                        //отправляем серверу запрос на удаление 
                        this.props.socketIo.emit("delete division info", { 
                            arguments: { 
                                divisionId: this.deleteEntityOptions.entityID,
                                organizationId: this.state.objectShowedInformation.id
                            }
                        });
                    }

                    return;
                }
            }

        }

        console.log(`отправляем серверу запрос для 'УДАЛЕНИЯ' информации из БД, ${request}`);
    }

    closeModalWindowSourceDel(){
        this.setState({ modalWindowSourceDel: false });

        this.alertMessage = { header: "", msg: "" };
        this.setState({ showModalAlert: false });
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

        console.log("====================");
        console.log(this.state.showModalAlert);
        console.log(this.alertMessage);
        console.log("++++++++++++++++++++");

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
                    showAlert={this.state.showModalAlert}
                    alertMessage={this.alertMessage}
                    onHide={this.closeModalWindowSourceDel}
                    msgBody={`Вы действительно хотите удалить ${(this.deleteEntityOptions.entityType === "organization") ? "организацию":"подразделение"} '${this.deleteEntityOptions.name}'`}
                    msgTitle={"Удаление"}
                    nameDel=""
                    handlerConfirm={this.handlerEntityDelete} />
            </React.Fragment>
        );
    }
}

CreateBodyManagementEntity.propTypes ={
    socketIo: PropTypes.object.isRequired,
    listShortEntity: PropTypes.object.isRequired,
    listFieldActivity: PropTypes.array.isRequired,
};

