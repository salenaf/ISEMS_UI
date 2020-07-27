"use strict";

import React from "react";
import { Button, Col, Table, Row, Modal, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowListTaskDownloadFiles extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            taskID: "",
            fullSizeListFile: 0,
            listFile: [],
        };

        this.handlerEvents.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {

            if(msg.type !== "downloadProcessing" && msg.type !== "filtrationProcessing"){
                console.log(msg);
            }

            if(msg.type === "listFilesByTaskID"){
                console.log("--- received file list ---");
                console.log(msg.options);
                console.log("--------------------------");

                this.setState({
                    taskID: msg.options.tid,
                    fullSizeListFile: msg.options.fls,
                    listFile: msg.options.lf,
                });
            }
        });
    }

    /**
     * сделать обработчики на кнопки
     * и обработчик на подгрузку данных при скроле
     */

    createModalBody(){
        let createList = () => {
            let formaterInt = new Intl.NumberFormat();
            let num = 0;

            return this.state.listFile.map((item) => {
                let fileLoaded = (item.file_loaded)? <span className="text-success">загружен</span>: <span className="text-danger">не выгружался</span>;

                return (
                    <tr key={`tr_${item.file_hex}`}>
                        <td><small>{++num}</small></td>
                        <td><small>{item.file_name}</small></td>
                        <td className="text-right">
                            <small>{formaterInt.format(item.file_size)}</small>
                        </td>
                        <td><small>{fileLoaded}</small></td>
                        <td>checkbox</td>
                    </tr>
                );
            });
        };

        if(this.state.fullSizeListFile === 0){
            return (
                <Row>
                    <Col md={12} className="pt-2">
                        <div className="col-md-12 text-center">
                            <Spinner animation="border" role="status" variant="primary">
                                <span className="sr-only">Загрузка...</span>
                            </Spinner>
                        </div>
                    </Col>
                </Row>
            );
        }

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-right text-muted pt-2">
                        всего файлов: <span className="text-info">{this.state.fullSizeListFile}</span>
                    </Col>
                </Row>
                <Row>
                    <Col md={12}>
                        <Table size="sm" striped hover>
                            <thead>
                                <tr>
                                    <th></th>
                                    <th>имя файла</th>
                                    <th>размер (в байтах)</th>
                                    <th>статус</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                {createList()}
                            </tbody>
                        </Table>
                    </Col>
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
                        <h5>{`Скачивание файлов, источник №${this.props.shortTaskInfo.sourceID} (${this.props.shortTaskInfo.sourceName}).`}</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Row>
                        <Col md={12} className="text-right">
                            <Button 
                                className="mr-2"
                                variant="outline-secondary" 
                                onClick={this.props.handlerButtonSubmit} 
                                size="sm">
                                скачать выбранное
                            </Button>
                            <Button 
                                variant="outline-primary" 
                                onClick={this.props.onHide} 
                                size="sm">
                                скачать всё
                            </Button>
                        </Col>
                    </Row>
                    {this.createModalBody.call(this)}
                </Modal.Body>
                <Modal.Footer></Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowListTaskDownloadFiles.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
    shortTaskInfo:PropTypes.object.isRequired,
    handlerButtonSubmit: PropTypes.func.isRequired,
};