import React from "react";
import { Accordion, Card, Button, Col, Form, Modal, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowSourceInfo extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "receivedInformation": false,
        };

        this.fullInformationAboutSource = {},

        this.windowClose = this.windowClose.bind(this);
        this.createBodyElement = this.createBodyElement.bind(this);
        
        this.listenerSocketIoConnect.call(this);
    }

    windowClose(){
        this.props.onHide();
    }

    /*
        только для эмуляции загрузки (delete in production)
    */
    emulatorDownloading(){
        if(!this.props.show) return;
        
        setTimeout(() => {
            this.setState({ receivedInformation: true });
        }, 2000);
    }

    listenerSocketIoConnect(){
        //Пока что эмулируем загрузку информации по сети
    }

    createBodyElement(){
        let isAnotherSource = this.emulatorDownloadingTestSource !== this.props.settings.id;
        if(!this.state.receivedInformation && isAnotherSource){
            return (
                <div className="row">
                    <div className="col-md-12 text-center">
                        Источник №{this.props.settings.id}, загрузка информации...
                    </div>
                    <div className="col-md-12 text-center">
                        <Spinner animation="border" role="status">
                            <span className="sr-only">Загрузка...</span>
                        </Spinner>
                    </div>
                </div>
            );
        }

        let sid = this.props.settings.id;
        let sourceInfo = this.props.sourceInfoForTest;

        console.log(sourceInfo[sid]);

        return (
            <React.Fragment>
                <div className="col-md-12 text-center"><strong>Источник № {sid} ({sourceInfo[sid].shortName})</strong></div>
                <Accordion defaultActiveKey="2">
                    <Card>
                        <Accordion.Toggle as={Card.Header} eventKey="0">
                            Информация об организации
                        </Accordion.Toggle>
                        <Accordion.Collapse eventKey="0">
                            <Card.Body>
                                <div className="col-md-12 text-center"><strong>{sourceInfo[sid].organization.name}</strong></div>
                                <div className="row">
                                    <div className="col-md-12 text-left">
                                        Добавлено: <em>{sourceInfo[sid].organization.dateRegister.split(" ")[0]}</em>,&nbsp;
                                        последнее изменение: <em>{sourceInfo[sid].organization.dateChange.split(" ")[0]}</em>&nbsp;
                                        в <em>{sourceInfo[sid].organization.dateChange.split(" ")[1]}</em>
                                    </div>
                                    <div className="col-md-4 text-right"><small>Подразделений:</small></div>
                                    <div className="col-md-8 text-left">
                                        {sourceInfo[sid].organization.countDivision}
                                    </div>
                                    <div className="col-md-4 text-right"><small>Вид деятельности:</small></div>
                                    <div className="col-md-8 text-left">
                                        {sourceInfo[sid].organization.fieldActivity}
                                    </div>        
                                    <div className="col-md-4 text-right"><small>Юридический адрес:</small></div>
                                    <div className="col-md-8 text-left">
                                        {sourceInfo[sid].organization.legalAddress}
                                    </div>
                                </div>
                            </Card.Body>
                        </Accordion.Collapse>
                    </Card>
                    <Card>
                        <Accordion.Toggle as={Card.Header} eventKey="1">
                            Информация о подразделении или филиале организации
                        </Accordion.Toggle>
                        <Accordion.Collapse eventKey="1">
                            <Card.Body>
                                <div className="col-md-12 text-center"><strong>{sourceInfo[sid].division.name}</strong></div>
                                <div className="row">
                                    <div className="col-md-12 text-left">
                                        Добавлено: <em>{sourceInfo[sid].division.dateRegister.split(" ")[0]}</em>,&nbsp;
                                        последнее изменение: <em>{sourceInfo[sid].division.dateChange.split(" ")[0]}</em>&nbsp;
                                        в <em>{sourceInfo[sid].division.dateChange.split(" ")[1]}</em>
                                    </div>
                                    <div className="col-md-4 text-right"><small>Установленных источников:</small></div>
                                    <div className="col-md-8 text-left">
                                        {sourceInfo[sid].division.countSources}
                                    </div>
                                    <div className="col-md-4 text-right"><small>Физический адрес:</small></div>
                                    <div className="col-md-8 text-left">
                                        {sourceInfo[sid].division.physicalAddress}
                                    </div>
                                    <div className="col-md-4 text-right"><small>Примечание:</small></div>
                                    <div className="col-md-8 text-left">
                                        {sourceInfo[sid].division.description}
                                    </div>
                                </div>
                            </Card.Body>
                        </Accordion.Collapse>
                    </Card>
                    <Card>
                        <Accordion.Toggle as={Card.Header} eventKey="2">
                            Информация по источнику № {sid}
                        </Accordion.Toggle>
                        <Accordion.Collapse eventKey="2">
                            <Card.Body>
                                <Form>              
                                    <Form.Row>
                                        <div className="col-md-12 text-left">
                                        Установлен: <em>{sourceInfo[sid].dateRegister.split(" ")[0]}</em>,&nbsp;
                                        последнее изменение: <em>{sourceInfo[sid].dateChange.split(" ")[0]}</em>&nbsp;
                                        в <em>{sourceInfo[sid].dateChange.split(" ")[1]}</em>
                                        </div>
                                        <div className="col-md-12 text-left">Сетевые настройки:</div>
                                        <div className="col-md-3 text-right"><small>ip адрес:</small></div>
                                        <div className="col-md-9 text-left">
                                            {sourceInfo[sid].networkSettings.ip}
                                        </div>
                                        <div className="col-md-3 text-right"><small>сетевой порт:</small></div>
                                        <div className="col-md-9 text-left">
                                            {sourceInfo[sid].networkSettings.port}
                                        </div>
                                        <div className="col-md-3 text-right"><small>токен:</small></div>
                                        <div className="col-md-9 text-left">
                                            {sourceInfo[sid].networkSettings.tokenID}
                                        </div>
                                        <div className="col-md-12 text-left">Общие настройки:</div>
                                        <div className="col-md-3 text-right"><small>архитектура:</small></div>
                                        <div className="col-md-9 text-left">
                                            {sourceInfo[sid].sourceSettings.architecture}
                                        </div>
                                        <div className="col-md-3 text-right"><small>телеметрия:</small></div>
                                        <div className="col-md-9 text-left">
                                            {(sourceInfo[sid].sourceSettings.telemetry) ? "включена": <span className="text-danger">выключена</span>}
                                        </div>
                                        <div className="col-md-3 text-right"><small>количество задач:</small></div>
                                        <div className="col-md-9 text-left">
                                            {sourceInfo[sid].sourceSettings.maxNumFilter}
                                        </div>
                                        <div className="col-md-3 text-right"><small>тип сетевого канала:</small></div>
                                        <div className="col-md-9 text-left">
                                            {sourceInfo[sid].sourceSettings.typeChannelLayerProto}
                                        </div>
                                        <div className="col-md-3 text-right"><small>Примечание:</small></div>
                                        <div className="col-md-9 text-left">
                                            {sourceInfo[sid].description}
                                        </div>
                                    </Form.Row>
                                </Form>
                            </Card.Body>
                        </Accordion.Collapse>
                    </Card>
                </Accordion>
                <br />
                <div className="col-md-12 text-right">
                    <Button variant="outline-primary" onClick={this.windowClose}>Закрыть</Button>
                </div>
            </React.Fragment>
        );
    }

    /**
     * 
     * <Form.Group controlId="formPlaintextEmail">
                        <Form.Label column sm="2">
                                Email
                        </Form.Label>
                        <Col sm="10">
                            <Form.Control plaintext readOnly defaultValue="email@example.com" />
                        </Col>
                    </Form.Group>
     * 
100: {
        "id": "ffeo0393f94h8884h494g4g",
        "shortName": "RosAtom COD 1",
        "dateRegister": "2019-08-13 14:39:08",
        "dateChange": "2020-01-02 10:45:43",
        "division": {
            "name": "Центр обработки данных №1",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 11:45:43",
            "physicalAddress": "г.Москва, ул. Удальцова, д.3",
            "description": "какие то замечания или описание...",
        },
        "organization": {
            "name": "Государственная корпорация атомной энергии Росатом",
            "dateRegister": "2019-08-12 11:32:08",
            "dateChange": "2020-01-03 03:15:43",
            "fieldActivity": "атомная промышленность",
            "legalAddress": "123482 г. Москва, Дмитровское шоссе, д. 67, к. 3" 
        },
        "networkSettings": { 
            "ip": "12.63.55.9", 
            "port": 13113, 
            "tokenID": "ffffoeo39fj94j949tj949j94j9tj4t", 
        },
        "sourceSettings": {
            "architecture": "client",
            "telemetry": false,
            "maxNumFilter": 3,
            "typeChannelLayerProto": "ip",
            "listDirWithFileNetworkTraffic": ["/__CURRENT_DISK_1","/__CURRENT_DISK_2", "/__CURRENT_DISK_3"],
        },
        "infoAboutApp": {
            "versionApp": "v1.4.4",
            "releaseApp": "12.12.2019",
        },
    },
 */
    render(){       
        this.emulatorDownloading.call(this);

        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg"
            >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Информация</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>{this.createBodyElement()}</Modal.Body>
            </Modal>
        );
    }
}

ModalWindowSourceInfo.propTypes = {
    settings: PropTypes.object,
    show: PropTypes.bool,
    onHide: PropTypes.func,
    sourceInfoForTest: PropTypes.object,
};