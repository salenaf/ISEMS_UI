import React from "react";
import { Accordion, Button, Card, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

class ShowEntityInformation extends React.Component {
    constructor(props){
        super(props);

        this.showInformation = this.showInformation.bind(this);
    }

    showInformation(){
        if(!this.props.showInfo){
            return;
        }
    
        /**
 * из полученной информации содержащейся в объекте
 * this.props.resivedInfo сформировать 'Аккардион' по образцу
 */

        //только для теста
        return <div>{JSON.stringify(this.props.resivedInfo)}</div>;
    }

    render(){
        return <Row>{this.showInformation()}</Row>;
    }
}

ShowEntityInformation.propTypes = {
    showInfo: PropTypes.bool,
    resivedInfo: PropTypes.object,
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
        };

        this.listSourceName = this.createListSource.call(this);

        this.handlerSelected = this.handlerSelected.bind(this);

        this.objectTestShowedInformation = {};
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

    handlerSelected(obj){
        console.log("func 'handlerSelected', START");
        console.log(JSON.stringify(obj));

        /**
         * Только для макета из оъекта 'listSourcesInformation' формируем объект 
         * содержащий информацию для вывода на страницу.
         * 
         * !!! В Production готовый объект с информацией будет приходить с сервера !!!
         */

        //это для теста!!
        this.objectTestShowedInformation = obj;

        /* 
теперь выполнить поиск полученного ID в this.props.listSourcesInformation и записать найденную
информацию в объект this.objectTestShowedInformation
*/

        this.objectTestShowedInformation = this.searchInfo_test.call(this);

        this.setState({ showInfo: true });
    }

    searchInfo_test(){
        /**
 * Искать информацию в this.props.listSourcesInformation
 */
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
                    resivedInfo={this.objectTestShowedInformation}/>
                <Row>
                    НИЖЕ ТОЛЬКО ОБРАЗЕЦ
                    <Col md={{ span: 9, offset: 1 }}>
                        <Accordion defaultActiveKey="0" style={{ width: "55rem" }}>
                            <Card border="info">
                                <Accordion.Toggle as={Card.Header} eventKey="0">
                                Государственная корпорация атомной энергии Росатом
                                </Accordion.Toggle>
                                <Accordion.Collapse eventKey="0">
                                    <Card.Body>
                                        <Row>
                                            <Col>
                                                {/*                                    <Form.Label><small>Название</small></Form.Label> */}
                                                <Form.Control type="text" defaultValue={"Государственная корпорация атомной энергии Росатом"}></Form.Control>
                                            </Col>
                                            <Col>
                                                {/*                                    <Form.Label><small>Юридический адрес</small></Form.Label> */}
                                                <Form.Control as="textarea" id="legal_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                            </Col>
                                        </Row>
                                        <Row>
                                            <Col>
                                                {/*                                    <Form.Label><small>Вид деятельности</small></Form.Label> */}
                                                <Form.Control as="select" size="sm">
                                                    <option key="0">...</option>
                                                    <option key="1">атомная промышленность</option>
                                                </Form.Control>
                                            </Col>
                                            <Col></Col>
                                        </Row>
                                        <Row>
                                            <Col className="text-right">
                                                <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                                <Button variant="outline-danger" size="sm">удалить</Button>
                                            </Col>
                                        </Row>
                                    </Card.Body>
                                </Accordion.Collapse>
                            </Card>
                            <Card border="dark">
                                <Accordion.Toggle as={Card.Header} eventKey="1">
                                Центр обработки данных 1
                                </Accordion.Toggle>
                                <Accordion.Collapse eventKey="1">
                                    <Card.Body>
                                        <Row>
                                            <Col>
                                                <Form.Control type="text" defaultValue={"Центр обработки данных 1"}></Form.Control>
                                            </Col>
                                            <Col>
                                                <Form.Control as="textarea" id="physical_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                            </Col>
                                        </Row>
                                        <Row>
                                            <Col md={6}><Form.Control as="textarea" id="legal_address" defaultValue={"Какие то заметки"}></Form.Control></Col>
                                            <Col md={2} className="text-left">источники:</Col>
                                            <Col md={4} className="text-left">
                                                <ul>
                                                    <li>1002 RSNet</li>
                                                    <li>1038 AO Smolensk</li>
                                                </ul>
                                            </Col>
                                        </Row>
                                        <Row>
                                            <Col className="text-right">
                                                <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                                <Button variant="outline-danger" size="sm">удалить</Button>
                                            </Col>
                                        </Row>
                                    </Card.Body>
                                </Accordion.Collapse>
                            </Card>
                            <Card border="dark">
                                <Accordion.Toggle as={Card.Header} eventKey="2">
                                Центр обработки данных 2
                                </Accordion.Toggle>
                                <Accordion.Collapse eventKey="2">
                                    <Card.Body>
                                        <Row>
                                            <Col>
                                                <Form.Control type="text" defaultValue={"Центр обработки данных 2"}></Form.Control>
                                            </Col>
                                            <Col>
                                                <Form.Control as="textarea" id="physical_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                            </Col>
                                        </Row>
                                        <Row>
                                            <Col md={6}><Form.Control as="textarea" id="legal_address" defaultValue={"Какие то заметки"}></Form.Control></Col>
                                            <Col md={2} className="text-left">источники:</Col>
                                            <Col md={4} className="text-left"></Col>
                                        </Row>
                                        <Row>
                                            <Col className="text-right">
                                                <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                                <Button variant="outline-danger" size="sm">удалить</Button>
                                            </Col>
                                        </Row>
                                    </Card.Body>
                                </Accordion.Collapse>
                            </Card>
                        </Accordion>
                    </Col>
                </Row>
            </React.Fragment>
        );
    }
}

CreateBodyManagementEntity.propTypes ={
    listSourcesInformation: PropTypes.object.isRequired,
};

