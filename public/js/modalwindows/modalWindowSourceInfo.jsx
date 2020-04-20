"use strict";

import React from "react";
import { Accordion, Badge, Button, Card, Form, Modal, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowSourceInfo extends React.Component {
    constructor(props){
        super(props);

        this.state = { "receivedInformation": false };

        this.fullInformationAboutSource = {};

        this.windowClose = this.windowClose.bind(this);
        this.getListDirectory = this.getListDirectory.bind(this);
        this.createMajorBobyElemet = this.createMajorBobyElemet.bind(this);
        
        this.listenerSocketIoConnect.call(this);
    }

    windowClose(){
        this.props.onHide();
        this.setState({ "receivedInformation": false });
        this.fullInformationAboutSource = {};
    }

    listenerSocketIoConnect(){
        this.props.socketIo.on("entity: set info about source", (data) => {
            this.fullInformationAboutSource = data.arguments;
            this.setState({ receivedInformation: true });
        });
    }

    getListDirectory(s){
        return (
            <ul>
                {s.source_settings.list_directories_with_file_network_traffic.map((item) => {
                    return <li type="1" key={`lf_${item}`}>{item}</li>;
                })}
            </ul>
        );
    }

    createMajorBobyElemet(){
        if(!this.state.receivedInformation){
            return (
                <div className="row">
                    <div className="col-md-12 text-center">
                    Источник №{this.props.settings.sourceID}, загрузка информации...
                    </div>
                    <div className="col-md-12 text-center">
                        <Spinner animation="border" role="status" variant="primary">
                            <span className="sr-only">Загрузка...</span>
                        </Spinner>
                    </div>
                </div>
            );
        }

        let formatter = Intl.DateTimeFormat("ru-Ru", {
            timeZone: "Europe/Moscow",
            day: "numeric",
            month: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "numeric",
        });
        let { source: s, division: d, organization: o } = this.fullInformationAboutSource;

        return (
            <React.Fragment>
                <div className="col-md-12 text-center"><strong>Источник № {s.source_id} ({s.short_name})</strong></div>
                <Accordion defaultActiveKey="2">
                    <Card>
                        <Accordion.Toggle as={Card.Header} eventKey="0">
                            Информация об организации
                        </Accordion.Toggle>
                        <Accordion.Collapse eventKey="0">
                            <Card.Body>
                                <div className="col-md-12 text-center"><strong>{o.name}</strong></div>
                                <div className="row">
                                    <div className="col-md-12 text-left">
                                        Добавлено: <em>{formatter.format(o.date_register)}</em>,&nbsp;
                                        последнее изменение: <em>{formatter.format(o.date_change)}</em>
                                    </div>
                                    <div className="col-md-4 text-right"><small>Подразделений:</small></div>
                                    <div className="col-md-8 text-left">
                                        {o.division_or_branch_list_id.length}
                                    </div>
                                    <div className="col-md-4 text-right"><small>Вид деятельности:</small></div>
                                    <div className="col-md-8 text-left">
                                        {o.field_activity}
                                    </div>        
                                    <div className="col-md-4 text-right"><small>Юридический адрес:</small></div>
                                    <div className="col-md-8 text-left">
                                        {o.legal_address}
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
                                <div className="col-md-12 text-center"><strong>{d.name}</strong></div>
                                <div className="row">
                                    <div className="col-md-12 text-left">
                                        Добавлено: <em>{formatter.format(d.date_register)}</em>,&nbsp;
                                        последнее изменение: <em>{formatter.format(d.date_change)}</em>
                                    </div>
                                    <div className="col-md-4 text-right"><small>Установленных источников:</small></div>
                                    <div className="col-md-8 text-left">
                                        {d.source_list.length}
                                    </div>
                                    <div className="col-md-4 text-right"><small>Физический адрес:</small></div>
                                    <div className="col-md-8 text-left">
                                        {d.physical_address}
                                    </div>
                                    <div className="col-md-4 text-right"><small>Примечание:</small></div>
                                    <div className="col-md-8 text-left">
                                        {d.description}
                                    </div>
                                </div>
                            </Card.Body>
                        </Accordion.Collapse>
                    </Card>
                    <Card>
                        <Accordion.Toggle as={Card.Header} eventKey="2">
                            Информация по источнику № {s.source_id}
                        </Accordion.Toggle>
                        <Accordion.Collapse eventKey="2">
                            <Card.Body>
                                <Form>              
                                    <Form.Row>
                                        <div className="col-md-12 text-left">
                                            Установлен: <em>{formatter.format(s.date_register)}</em>,&nbsp;
                                            последнее изменение: <em>{formatter.format(s.date_change)}</em>
                                        </div>
                                        <div className="col-md-12 text-left">Сетевые настройки:</div>
                                        <div className="col-md-3 text-right"><small>ip адрес:</small></div>
                                        <div className="col-md-9 text-left">
                                            {s.network_settings.ipaddress}
                                        </div>
                                        <div className="col-md-3 text-right"><small>сетевой порт:</small></div>
                                        <div className="col-md-9 text-left">
                                            {s.network_settings.port}
                                        </div>
                                        <div className="col-md-3 text-right"><small>токен:</small></div>
                                        <div className="col-md-9 text-center alert-info">
                                            {s.network_settings.token_id}
                                        </div>
                                        <div className="col-md-12 text-left">Общие настройки:</div>
                                        <div className="col-md-3 text-right"><small>архитектура:</small></div>
                                        <div className="col-md-9 text-left">
                                            {(s.source_settings.type_architecture_client_server === "client") ? <Badge variant="dark">{s.source_settings.type_architecture_client_server}</Badge> : <Badge variant="primary">{s.source_settings.type_architecture_client_server}</Badge>}
                                        </div>
                                        <div className="col-md-3 text-right"><small>телеметрия:</small></div>
                                        <div className="col-md-9 text-left">
                                            {(s.source_settings.transmission_telemetry) ? <Badge variant="primary">включена</Badge> : <Badge variant="danger">выключена</Badge>}
                                        </div>
                                        <div className="col-md-3 text-right"><small>количество задач:</small></div>
                                        <div className="col-md-9 text-left">
                                            {s.source_settings.maximum_number_simultaneous_filtering_processes}
                                        </div>
                                        <div className="col-md-3 text-right"><small>тип сетевого канала:</small></div>
                                        <div className="col-md-9 text-left">
                                            {s.source_settings.type_channel_layer_protocol}
                                        </div>
                                        <div className="col-md-3 text-right"><small>список директорий:</small></div>
                                        <div className="col-md-9 text-left">
                                            {this.getListDirectory(s)}
                                        </div>
                                        <div className="col-md-3 text-right"><small>Примечание:</small></div>
                                        <div className="col-md-9 text-left">
                                            {s.description}
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

    render(){       
        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Информация</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>{this.createMajorBobyElemet()}</Modal.Body>
            </Modal>
        );
    }
}

ModalWindowSourceInfo.propTypes = {
    settings: PropTypes.object,
    show: PropTypes.bool,
    onHide: PropTypes.func,
    socketIo: PropTypes.object,
};