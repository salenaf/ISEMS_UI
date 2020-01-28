import React from "react";
import { Accordion, Button, Breadcrumb, Card, Form } from "react-bootstrap";
import PropTypes from "prop-types";

import ModalWindowAddEntity from "../../modalwindows/modalWindowAddEntity.jsx";

class ButtonSaveNewEntity extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        if(!this.props.showButton){
            return <div></div>;
        }

        return <Button onClick={this.props.handler} variant="outline-success" size="sm">сохранить</Button>;
    }
}

ButtonSaveNewEntity.propTypes = {
    showButton: PropTypes.bool,
    handler: PropTypes.func.isRequired,
};

export default class CreateBodyNewEntity extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            addedNewEntity: false,
            showModalWindow: false,
            chosenDivisionID: null,
            chosenOrganizationID: null,
            listOrganizationName: this.createListOrganization.call(this),
            listDivisionName: this.createListDivision.call(this),
        };

        this.modalWindowSettings = {
            listFieldActivity: this.getListFieldActivity.call(this),
        };

        this.handelrButtonAdd = this.handelrButtonAdd.bind(this);
        this.closeModalWindow = this.closeModalWindow.bind(this);
        this.createListElementDivision = this.createListElementDivision.bind(this);
        this.createListElementOrganization = this.createListElementOrganization.bind(this);
    }

    getListFieldActivity(){
        let objTmp = {};
        for(let source in this.props.listSourcesInformation){
            objTmp[this.props.listSourcesInformation[source].fieldActivity] = "";
        }

        return objTmp;
    }

    isDisabledDelete(){

        /**
        * Проверить добавилась ли новая сущность!!!
        */

        let isChecked = false;

        return (isChecked) ? "" : "disabled";
    }

    handelrButtonAdd(){
        let typeEntity = "source";

        if(this.state.chosenOrganizationID === null){
            typeEntity = "organization";
        } else if(this.state.chosenOrganizationID !== null && this.state.chosenDivisionID === null){
            typeEntity = "division";
        }

        this.showModalWindow.call(this, typeEntity);
    }

    showModalWindow(typeEntity){

        console.log(`Открыто модальное окно для сущности '${typeEntity}'`);

        const listTypeEntity = {
            "organization": {
                name: "организацию",
            },
            "division": {
                name: "подразделение или филиал",
            },
            "source": {
                name: "источник",
            },
        };

        this.resultBody = this.resultBody.bind(this);
        this.sendInfoNewEntity = this.sendInfoNewEntity.bind(this);

        this.modalWindowSettings.type = typeEntity;
        this.modalWindowSettings.name = listTypeEntity[typeEntity].name;
        
        this.setState({ showModalWindow: true });    
    }

    closeModalWindow(){
        this.setState({ showModalWindow: false });
    }

    selectedOrganization(e){

        console.log(`Была выбрана организация с ID: ${e.target.value}`);

        this.setState({ chosenOrganizationID: e.target.value });
    }

    selectedDivision(e){

        console.log(`Была выбрано подразделение с ID: ${e.target.value}`);

        this.setState({ chosenDivisionID: e.target.value });
    }

    createListOrganization(){
        console.log("createListOrganization START...");

        let listTmp = {};
        for(let source in this.props.listSourcesInformation){
            listTmp[this.props.listSourcesInformation[source].organization] = this.props.listSourcesInformation[source].oid;
        }

        return listTmp;
    }

    createListDivision(){
        console.log("createListDivision START...");

        let listTmp = {};
        for(let source in this.props.listSourcesInformation){
            listTmp[this.props.listSourcesInformation[source].division] = {
                did: this.props.listSourcesInformation[source].did,
                oid: this.props.listSourcesInformation[source].oid,
            };
        }

        return listTmp;
    }

    createListElementOrganization(){
        let selectForm = "";
        let lsi = this.state.listOrganizationName;

        let listName = Object.keys(lsi);
        listName.sort();

        let listOptions = listName.map((name) => {
            return <option value={lsi[name]} key={`select_${lsi[name]}_option`}>{name}</option>;
        });

        selectForm = <Form.Group onChange={this.selectedOrganization.bind(this)} controlId={"select_list_organization"}>
            <Form.Label>Организация</Form.Label>
            <Form.Control as="select" size="sm">
                <option value="all" key={"select_organization_option_none"}>...</option>
                {listOptions}
            </Form.Control>
        </Form.Group>;

        return selectForm;
    }

    createListElementDivision(){
        let selectForm = "";       
        let lsi = {};
       
        for(let nameDivision in this.state.listDivisionName){
            if(this.state.chosenOrganizationID === null || this.state.chosenOrganizationID === "all"){
                lsi[nameDivision] = this.state.listDivisionName[nameDivision].did;

                continue;
            }

            if(this.state.chosenOrganizationID === this.state.listDivisionName[nameDivision].oid){
                lsi[nameDivision] = this.state.listDivisionName[nameDivision].did;
            }
        }        

        let listName = Object.keys(lsi);
        listName.sort();

        let listOptions = listName.map((name) => {
            return <option value={lsi[name]} key={`select_${lsi[name]}_option`}>{name}</option>;
        });

        selectForm = <Form.Group onChange={this.selectedDivision.bind(this)} controlId={"select_list_division"}>
            <Form.Label>Подразделение или филиал организации</Form.Label>
            <Form.Control as="select" size="sm">
                <option value={null} key={"select_division_option_none"}>...</option>
                {listOptions}
            </Form.Control>
        </Form.Group>;

        return selectForm;
    }

    sendInfoNewEntity(){
        console.log("Отправляем информацию о новых сущностях");
    }

    resultBody(){
        return "сюда будут добавлятся новые сущности !!! МОЖЕТ СДЕЛАТЬ ОДНУ КНОПКУ КОТОРАЯ В ЗАВИСИМОСТИ ОТ ВЫБРАННОГО ЭЛЕМЕНТА В СПИСКАХ БУДЕТ ОТКРЫВАТь СООТВЕТСТВУЮЩЕЕ ОКНО ???";
    }

    render(){
        return (
            <React.Fragment>
                <br/>
                <div className="row">
                    <div className="col-md-12 text-left">
                        <Form>
                            {this.createListElementOrganization()}
                            {this.createListElementDivision()}
                        </Form>
                    </div>
                </div>
                <div className="row">
                    <div className="col-md-12 text-right">
                        <Button size="sm" variant="outline-primary" onClick={this.handelrButtonAdd}>добавить</Button>
                    </div>
                </div>
                <div className="row">
                    <br/>
                    {this.resultBody()}
                    <br/>
                    <Accordion>
                        <Card>
                            <Card.Header>
                                <Accordion.Toggle as={Button} variant="link" eventKey="0">
      Государственная корпорация атомной энергии Росатом
                                </Accordion.Toggle>
                            </Card.Header>
                            <Accordion.Collapse eventKey="0">
                                <Card.Body>Hello! I'm the body</Card.Body>
                            </Accordion.Collapse>
                        </Card>
                        <Card>
                            <Card.Header>
                                <Accordion.Toggle as={Button} variant="link" eventKey="1">
      Центр обработки данных №2
                                </Accordion.Toggle>
                            </Card.Header>
                            <Accordion.Collapse eventKey="1">
                                <Card.Body>Hello! I'm another body</Card.Body>
                            </Accordion.Collapse>
                        </Card>
                    </Accordion>
                    <br/>
                    <Breadcrumb>
                        <Breadcrumb.Item href="#">Home</Breadcrumb.Item>
                        <Breadcrumb.Item href="#">Library</Breadcrumb.Item>
                        <Breadcrumb.Item active>Data</Breadcrumb.Item>
                    </Breadcrumb>
                </div>
                <div className="row">
                    <div className="col-md-12 text-right">
                        <ButtonSaveNewEntity handler={this.sendInfoNewEntity} showButton={this.state.addedNewEntity} />
                    </div>
                </div>

                <ModalWindowAddEntity 
                    show={this.state.showModalWindow}
                    onHide={this.closeModalWindow}
                    settings={this.modalWindowSettings} />
            </React.Fragment>
        );
    }
}

CreateBodyNewEntity.propTypes ={
    listSourcesInformation: PropTypes.object.isRequired,
};