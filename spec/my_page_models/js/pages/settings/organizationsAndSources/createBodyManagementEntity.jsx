import React from "react";
import { Accordion, Button, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

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
        return this.props.resivedInfo.listDivision.map((item) => {
            return (
                <Card border="dark" key={`key_division_${item.name}`}>
                    <Accordion.Toggle as={Card.Header} eventKey={num}>{item.name}</Accordion.Toggle>
                    <Accordion.Collapse eventKey={num++}>
                        <Card.Body>
                            <Row>
                                <Col><Form.Control type="text" onChange={this.props.handlerInputChange} value={item.name} id={`name:${item.id}`}></Form.Control></Col>
                                <Col><Form.Control as="textarea" onChange={this.props.handlerInputChange} value={item.physicalAddress} id={`physical_address:${item.id}`}></Form.Control></Col>
                            </Row>
                            <Row>
                                <Col md={6}><Form.Control as="textarea" onChange={this.props.handlerInputChange} value={item.description} id={`description:${item.id}`}></Form.Control></Col>
                                <Col md={2} className="text-left">источники:</Col>
                                <Col md={4} className="text-left"><ul>{item.listSource.map((source) => <li key={`li_source_${source}`}>{source}</li>)}</ul></Col>
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
 
        let list = Object.keys(this.props.listFieldActivity);
        list.sort();

        let num = 1;

        console.log(this.props.listFieldActivity);
        console.log(this.props.resivedInfo);

        return (
            <Accordion defaultActiveKey="0" style={{ width: "55rem" }}>
                <Card border="info">
                    <Accordion.Toggle as={Card.Header} eventKey="0">{this.props.resivedInfo.name}</Accordion.Toggle>
                    <Accordion.Collapse eventKey="0">
                        <Card.Body>
                            <Row>
                                <Col><Form.Control type="text" onChange={this.props.handlerInputChange} defaultValue={this.props.resivedInfo.name} id="name"></Form.Control></Col>
                                <Col><Form.Control as="textarea" onChange={this.props.handlerInputChange} defaultValue={this.props.resivedInfo.legalAddress} id="legal_address"></Form.Control></Col>
                            </Row>
                            <Row>
                                <Col>
                                    <Form.Control as="select" onChange={this.props.handlerInputChange} value={this.props.resivedInfo.fieldActivity} id="field_activity" size="sm">
                                        <option value="" key="list_field_activity_0">...</option>
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
    listFieldActivity: PropTypes.object.isRequired,
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
        console.log("func 'handlerChoose'");

        if(typeof e.target === "undefined"){
            return;
        }

        if(typeof e.target.value === "undefined"){
            return;
        }

        let [ typeValue, valueID ] = e.target.value.split(":");

        console.log(`type:'${typeValue}', value:'${valueID}'`);

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
            <Form.Control onClick={this.handlerChoose} as="select" className="custom-select" size="sm">
                <option key="key_choose" value="0">выбрать...</option>
                <option key="key_organization_title" disabled>{"организации".toUpperCase()}</option>
                {this.listOrganization()}
                <option key="division_title" disabled>{"подразделения или филиалы".toUpperCase()}</option>
                {this.listDivision()}
                <option key="source_title" disabled>{"источники".toUpperCase()}</option>
                {this.listSource()}
            </Form.Control>
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
            listOrganizationName: this.createListOrganization.call(this),
            listDivisionName: this.createListDivision.call(this),
            objectShowedInformation: {},
        };

        this.listSourceName = this.createListSource.call(this);

        this.handlerSave = this.handlerSave.bind(this);
        this.handlerDelete = this.handlerDelete.bind(this);
        this.handlerSelected = this.handlerSelected.bind(this);
        this.handlerInputChange = this.handlerInputChange.bind(this);
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

    createListSource(){
        console.log("createListSource START...");

        let listTmp = {};
        for(let source in this.props.listSourcesInformation){
            listTmp[`${source} ${this.props.listSourcesInformation[source].shortName}`] = {
                sid: this.props.listSourcesInformation[source].sid,
                did: this.props.listSourcesInformation[source].did,
                oid: this.props.listSourcesInformation[source].oid,
            };
        }

        return listTmp;
    }

    getListFieldActivity(){
        let objTmp = {};
        for(let source in this.props.listSourcesInformation){
            objTmp[this.props.listSourcesInformation[source].fieldActivity] = "";
        }

        return objTmp;
    }

    searchInfoListSourceInformation_test({ type: searchType, value: searchID }){

        console.log("FUNC 'searchInfoListSourceInformation_test'");

        let paramType = {
            "organization": "oid",
            "division": "did",
            "source": "id",
        };
    
        let lsi = this.props.listSourcesFullInformation;
        let tmp = {};
        let oid = "";
    
        //получаем организацию
        for(let sourceID in lsi){
            if(lsi[sourceID][paramType[searchType]] === searchID){
                tmp.id = lsi[sourceID].oid;
                tmp.name = lsi[sourceID].organization.name;
                tmp.dateRegister = lsi[sourceID].organization.dateRegister;
                tmp.dateChange = lsi[sourceID].organization.dateChange;
                tmp.fieldActivity = lsi[sourceID].organization.fieldActivity;
                tmp.legalAddress = lsi[sourceID].organization.legalAddress;
                tmp.listDivision = [];
    
                oid = lsi[sourceID].oid;
    
                break;
            }
        }
    
        for(let sourceID in lsi){
            if(lsi[sourceID].oid === oid){
                let sourceListTmp = [];
                for(let sid in lsi){
                    if(lsi[sid].did === lsi[sourceID].did){
                        sourceListTmp.push(`${sid} ${lsi[sid].shortName}`);
                    }
                }
    
                tmp.listDivision.push({
                    "id": lsi[sourceID].did,
                    "name": lsi[sourceID].division.name,
                    "dateRegister": lsi[sourceID].division.dateRegister,
                    "dateChange": lsi[sourceID].division.dateChange,
                    "physicalAddress": lsi[sourceID].division.physicalAddress,
                    "description": lsi[sourceID].division.description,
                    "listSource": sourceListTmp,
                });
            }
        }

        return tmp;
    }

    handlerSelected(obj){
        console.log("func 'handlerSelected', START");
        console.log(obj);

        /**
         * Только для макета из оъекта 'listSourcesInformation' формируем объект 
         * содержащий информацию для вывода на страницу.
         * 
         * !!! В Production готовый объект с информацией будет приходить с сервера !!!
         */

        //ТОЛЬКО ДЛЯ ТЕСТА!!! ищем в объекте listSourcesInformation информацию по ID
        this.setState({objectShowedInformation: this.searchInfoListSourceInformation_test.call(this, obj)});
        this.setState({ showInfo: true });
    }

    handlerInputChange(e){
        console.log("func 'handlerInputChange', START...");
        console.log(`ID: ${e.target.id}, Value: ${e.target.value}`);

        /**
         * 
         *  !!!!!!!!!!!!!!! 
         * 
         * Непонятно работает обработчик ввода. При изменении названия организации, название меняется,
         * однако, при выборе из списка другой организации все поля меняются, кроме названия организации
         * помененной ранее.
         * При изменении названия подразделения, вводится только ОДИН символ, следующий символ можно ввести
         * только после повторного выделения поля
         */

        let pattern = {
            "name": "name",
            "legal_address": "legalAddress",
            "field_activity": "fieldActivity",
            "physical_address": "physicalAddress",
            "description": "description",
        };
        let tmpObj = this.state.objectShowedInformation;

        let [ name, ID ] = e.target.id.split(":");
        if(typeof ID === "undefined"){
            tmpObj[pattern[name]] = e.target.value;
        } else {
            for(let i = 0; i < tmpObj.listDivision.length; i++){
                if(tmpObj.listDivision[i].id === ID){
                    tmpObj.listDivision[i][pattern[name]] = e.target.value;
                }
            }
        }

        this.setState({ objectShowedInformation: tmpObj });
    }

    handlerSave(entityType, entityID){
        console.log("func 'handlerSave', START...");
        console.log(`отправляем серверу запрос для 'СОХРАНЕНИЯ' информации в БД, ${JSON.stringify({ action: "entity_save", entityType: entityType, entityID: entityID })}`);

    }

    handlerDelete(entityType, entityID){
        console.log("func 'handlerSave', START...");
        console.log(`отправляем серверу запрос для 'УДАЛЕНИЯ' информации из БД, ${JSON.stringify({ action: "entity_save", entityType: entityType, entityID: entityID })}`);

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
                    <Col>
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
                    listFieldActivity={this.getListFieldActivity.call(this)}
                    resivedInfo={this.state.objectShowedInformation}
                    handlerInputChange={this.handlerInputChange} />
            </React.Fragment>
        );
    }
}

CreateBodyManagementEntity.propTypes ={
    listSourcesInformation: PropTypes.object.isRequired,
    listSourcesFullInformation: PropTypes.object.isRequired,
};

