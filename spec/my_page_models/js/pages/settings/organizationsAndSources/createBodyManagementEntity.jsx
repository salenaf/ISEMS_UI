import React from "react";
import { Button, Card, Container, Col, Form, Row } from "react-bootstrap";
import PropTypes from "prop-types";

class CreateListEntity extends React.Component {
    constructor(props){
        super(props);

        this.listSource = this.listSource.bind(this);
        this.listDivision = this.listDivision.bind(this);
        this.listOrganization = this.listOrganization.bind(this);
    }

    listOrganization(){
        let arrayTmp = Object.keys(this.props.listOrganization).sort().map((name) => {
            return <option key={`key_org_${this.props.listOrganization[name]}`} value={this.props.listOrganization[name]}>{name}</option>;
        });

        return arrayTmp;
    }

    listDivision(){       
        let arrayTmp = Object.keys(this.props.listDivision).sort().map((name) => {
            return <option key={`key_divi_${this.props.listDivision[name].did}`} value={this.props.listDivision[name].did}>{name}</option>;
        });

        return arrayTmp;
    }

    listSource(){
        let arrayTmp = Object.keys(this.props.listSource).sort((a, b) => a < b).map((name) => {
            return <option key={`key_sour_${this.props.listSource[name].sid}`} value={this.props.listSource[name].sid}>{name}</option>;
        });

        return arrayTmp;
    }

    render(){
        return (
            <Form.Control as="select" className="custom-select" size="sm">
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
};

export default class CreateBodyManagementEntity extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            listOrganizationName: this.createListOrganization.call(this),
            listDivisionName: this.createListDivision.call(this),
        };

        this.listSourceName = this.createListSource.call(this);
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
                            listSource={this.listSourceName} />
                    </Col>
                </Row>
                <br/>
                <Container>
                    <Row className="justify-content-lg-center">                      
                        <Col md={{ span: 9, offset: 3 }}>
                            <Card border="info" style={{ width: "30rem" }}>
                                <Card.Header>Организация</Card.Header>
                                <Card.Body className="text-left">
                                    <Form.Label><small>Название</small></Form.Label>
                                    <Form.Control type="text" defaultValue={"Государственная корпорация атомной энергии Росатом"}></Form.Control>
                                    <Form.Label><small>Вид деятельности</small></Form.Label>
                                    <Form.Control as="select" size="sm">
                                        <option key="0">...</option>
                                        <option key="1">атомная промышленность</option>
                                    </Form.Control>
                                    <Form.Label><small>Юридический адрес</small></Form.Label>
                                    <Form.Control as="textarea" id="legal_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                </Card.Body>
                                <Card.Footer className="text-right">
                                    <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" size="sm">удалить</Button>
                                </Card.Footer>
                            </Card>
                        </Col>
                    </Row>
                    <br/>
                    <Row className="justify-content-lg-left">
                        <Col lg="auto">
                            <Card border="secondary" style={{ width: "30rem" }}>
                                <Card.Header>Подразделение или филиал</Card.Header>
                                <Card.Body className="text-left">
                                    <Form.Label><small>Название</small></Form.Label>
                                    <Form.Control type="text" defaultValue={"Центр обработки данных 1"}></Form.Control>
                                    <Form.Label><small>Физический адрес</small></Form.Label>
                                    <Form.Control as="textarea" id="physical_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                    <Form.Label><small>Примечание</small></Form.Label>
                                    <Form.Control as="textarea" id="legal_address" defaultValue={"Какие то заметки"}></Form.Control>
                                    <Col>источники:</Col>
                                    <Col>
                                        <ul>
                                            <li>1002 RSNet</li>
                                            <li>1038 AO Smolensk</li>
                                        </ul>
                                    </Col>
                                </Card.Body>
                                <Card.Footer className="text-right">
                                    <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" size="sm">удалить</Button>
                                </Card.Footer>
                            </Card>
                        </Col>
                        <Col lg="auto">
                            <Card border="secondary" style={{ width: "30rem" }}>
                                <Card.Header>Подразделение или филиал</Card.Header>
                                <Card.Body className="text-left">
                                    <Form.Label><small>Название</small></Form.Label>
                                    <Form.Control type="text" defaultValue={"Центр обработки данных 2"}></Form.Control>
                                    <Form.Label><small>Физический адрес</small></Form.Label>
                                    <Form.Control as="textarea" id="physical_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                    <Form.Label><small>Примечание</small></Form.Label>
                                    <Form.Control as="textarea" id="legal_address" defaultValue={"Какие то заметки"}></Form.Control>
                                    <Col>источники:</Col>
                                    <Col>

                                    </Col>
                                </Card.Body>
                                <Card.Footer className="text-right">
                                    <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" size="sm">удалить</Button>
                                </Card.Footer>
                            </Card>
                        </Col>
                    </Row>
                </Container>
                <br/>
                <Container>
                    <Row>                      
                        <Col md={4}>
                            <Card border="info" style={{ width: "30rem" }}>
                                <Card.Header>Организация</Card.Header>
                                <Card.Body className="text-left">
                                    <Form.Label><small>Название</small></Form.Label>
                                    <Form.Control type="text" defaultValue={"Государственная корпорация атомной энергии Росатом"}></Form.Control>
                                    <Form.Label><small>Вид деятельности</small></Form.Label>
                                    <Form.Control as="select" size="sm">
                                        <option key="0">...</option>
                                        <option key="1">атомная промышленность</option>
                                    </Form.Control>
                                    <Form.Label><small>Юридический адрес</small></Form.Label>
                                    <Form.Control as="textarea" id="legal_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                </Card.Body>
                                <Card.Footer className="text-right">
                                    <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" size="sm">удалить</Button>
                                </Card.Footer>
                            </Card>
                        </Col>
                        <Col md={{ span: 3, offset: 2 }}>
                            <Card border="secondary" style={{ width: "35rem" }}>
                                <Card.Header>Подразделение или филиал</Card.Header>
                                <Card.Body className="text-left">
                                    <Form.Label><small>Название</small></Form.Label>
                                    <Form.Control type="text" defaultValue={"Центр обработки данных 1"}></Form.Control>
                                    <Form.Label><small>Физический адрес</small></Form.Label>
                                    <Form.Control as="textarea" id="physical_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                    <Form.Label><small>Примечание</small></Form.Label>
                                    <Form.Control as="textarea" id="legal_address" defaultValue={"Какие то заметки"}></Form.Control>
                                    <Col>источники:</Col>
                                    <Col>
                                        <ul>
                                            <li>1002 RSNet</li>
                                            <li>1038 AO Smolensk</li>
                                        </ul>
                                    </Col>
                                </Card.Body>
                                <Card.Footer className="text-right">
                                    <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" size="sm">удалить</Button>
                                </Card.Footer>
                            </Card>
                            <Card border="secondary" style={{ width: "30rem" }}>
                                <Card.Header>Подразделение или филиал</Card.Header>
                                <Card.Body className="text-left">
                                    <Form.Label><small>Название</small></Form.Label>
                                    <Form.Control type="text" defaultValue={"Центр обработки данных 2"}></Form.Control>
                                    <Form.Label><small>Физический адрес</small></Form.Label>
                                    <Form.Control as="textarea" id="physical_address" defaultValue={"123482 г. Москва, Дмитровское шоссе, д. 67, к. 3"}></Form.Control>
                                    <Form.Label><small>Примечание</small></Form.Label>
                                    <Form.Control as="textarea" id="legal_address" defaultValue={"Какие то заметки"}></Form.Control>
                                    <Col>источники:</Col>
                                    <Col>

                                    </Col>
                                </Card.Body>
                                <Card.Footer className="text-right">
                                    <Button variant="outline-success" size="sm">сохранить</Button>&nbsp;
                                    <Button variant="outline-danger" size="sm">удалить</Button>
                                </Card.Footer>
                            </Card>
                        </Col>
                    </Row>
                </Container>
            </React.Fragment>
        );
    }
}

CreateBodyManagementEntity.propTypes ={
    listSourcesInformation: PropTypes.object.isRequired,
};

