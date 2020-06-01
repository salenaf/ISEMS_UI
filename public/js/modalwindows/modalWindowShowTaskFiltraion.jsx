"use strict";

import React from "react";
import { Button, Col, Modal, Row, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowShowTaskFiltraion extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showInfo: false,
            parametersFiltration: {},
            filteringStatus: {
                dateCreateTask: 0,
                dateFinishTask: 0,
            },
            downloadingStatus: {}
        };

        this.handlerEvents.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {
            if(msg.type === "processingGetAllInformationByTaskID"){
                console.log(msg.options);

                this.setState({
                    showInfo: true,
                    parametersFiltration: {},
                    filteringStatus: {
                        dateCreateTask: 0,
                        dateFinishTask: 0,
                    },
                    downloadingStatus: {}
                });
            }
        });
    }

    createModalBody(){
        if(!this.state.showInfo){
            return (
                <div className="col-md-12 text-center">
                    <Spinner animation="border" role="status" variant="primary">
                        <span className="sr-only">Загрузка...</span>
                    </Spinner>
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

        return (
            <React.Fragment>
                <Row>
                    <Col>Задача по фильтрации</Col>
                </Row>
                <Row>
                    <Col sm="6" className="mt-0 text-muted">
                        <small>задание добавлено: {formatter.format(this.state.dateCreateTask)}</small>
                    </Col>
                    <Col sm="6" className="mt-0 text-muted">
                        <small>завершено: {formatter.format(this.state.dateFinishTask)}</small>
                    </Col>
                </Row>
                <Row>
                    <Col sm="6" className="text-muted">
                        <small>параметры
                        </small></Col>
                    <Col sm="6" className="text-muted">
                        <small>ход выполнения</small>
                    </Col>
                </Row>
                <Row>
                    <Col>Задача по скачиванию файлов</Col>
                </Row>
            </React.Fragment>
        );
    }

    render(){
        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.props.onHide}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Источник №{this.props.shortTaskInfo.sourceID} ({this.props.shortTaskInfo.sourceName})</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    {this.createModalBody.call(this)}
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-danger" onClick={this.props.handlerButtonStopFiltering} size="sm">
                        остановить задачу
                    </Button>
                    <Button variant="outline-secondary" onClick={this.props.onHide} size="sm">
                        закрыть
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowShowTaskFiltraion.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    shortTaskInfo: PropTypes.object.isRequired,
    handlerButtonStopFiltering: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
};