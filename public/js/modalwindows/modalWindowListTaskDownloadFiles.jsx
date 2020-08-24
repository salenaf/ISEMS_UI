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
            listFileChecked: new Map,
            numFileChecked: 0,
            sizeFileChecked: 0,
            onScrollChunk: 1,
            disabledButtonNext: false,
        };

        this.formaterInt = new Intl.NumberFormat();

        this.buttonNext = this.buttonNext.bind(this);
        this.countAndSizeFileChecked = this.countAndSizeFileChecked.bind(this);
        this.handlerDownloadAllFiles = this.handlerDownloadAllFiles.bind(this);
        this.handlerNextChunkFileList = this.handlerNextChunkFileList.bind(this);
        this.handlerDownloadMarkerFiles = this.handlerDownloadMarkerFiles.bind(this);

        this.handlerEvents.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {
            if(msg.type === "listFilesByTaskID"){
                if((msg.options.tid !== this.state.taskID) || (msg.options.olp === 0)){
                    this.setState({
                        taskID: msg.options.tid,
                        fullSizeListFile: msg.options.fls,
                        listFile: msg.options.lf,
                        listFileChecked: new Map,
                        numFileChecked: 0,
                        sizeFileChecked: 0,
                        onScrollChunk: 1,
                        disabledButtonNext: false,
                    });

                    return;
                }

                let onScrollChunk = this.state.onScrollChunk + 1;
                let listFile = [].concat(this.state.listFile, msg.options.lf);

                this.setState({
                    taskID: msg.options.tid,
                    fullSizeListFile: msg.options.fls,
                    listFile: listFile,
                    onScrollChunk: onScrollChunk,
                    disabledButtonNext: false,
                });
            }
        });
    }

    handlerEvantsCheckbox(objInfo, e){
        let listFileChecked = this.state.listFileChecked;
        if(e.target.checked){
            if(listFileChecked.has(objInfo.fileName)){
                return;
            }

            listFileChecked.set(objInfo.fileName, objInfo.fileSize);
        } else {
            listFileChecked.delete(objInfo.fileName);    
        }

        let { num: nfc, size: sfc } = this.countAndSizeFileChecked();

        this.setState({
            listFileChecked: listFileChecked,
            numFileChecked: nfc,
            sizeFileChecked: sfc,
        });
    }

    handlerDownloadAllFiles(){      
        this.props.socketIo.emit("network interaction: start downloading files", {
            arguments: { 
                o: {
                    id: this.props.shortTaskInfo.sourceID,
                    tidapp: this.state.taskID,
                    fl: [],
                }
            } 
        });

        this.props.onHide();
    }

    handlerDownloadMarkerFiles(){
        if(this.state.listFileChecked.size === 0){
            return;
        }

        let fileList = [];
        for(let fn of this.state.listFileChecked.keys()){
            fileList.push(fn);
        }

        this.props.socketIo.emit("network interaction: start downloading files", {
            arguments: { 
                o: {
                    id: this.props.shortTaskInfo.sourceID,
                    tidapp: this.state.taskID,
                    fl: fileList,
                }
            } 
        });

        this.props.onHide();
    }

    handlerNextChunkFileList(){
        //отправляем запрос
        this.props.socketIo.emit("network interaction: get a list of files for a task", {
            arguments: { 
                taskID: this.state.taskID,
                partSize: 25,
                offsetListParts: this.state.onScrollChunk*25,
            } 
        });

        //выключаем кнопку 'ещё' пока запрос не будет выполнен
        this.setState({ disabledButtonNext: false });
    }

    buttonNext(){
        if(this.state.listFile.length === this.state.fullSizeListFile){
            return;
        }

        return (
            <Row>
                <Col md={12}>
                    <Button 
                        className="mr-2"
                        variant="light" 
                        onClick={this.handlerNextChunkFileList} 
                        disabled={this.state.disabledButtonNext}
                        size="sm">
                                ещё...
                    </Button>
                </Col>
            </Row>
        );
    }

    countAndSizeFileChecked() {
        let tmp = { num: 0, size: 0 };
        for(let item of this.state.listFileChecked.values()){
            tmp.num += 1;
            tmp.size += item;
        }

        return tmp;
    }

    createModalBody(){
        let createList = () => {
            let num = 0;

            return this.state.listFile.map((item) => {
                let fileLoaded = (item.file_loaded)? <span className="text-success">загружен</span>: <span className="text-danger">не выгружался</span>;

                return (
                    <tr key={`tr_${item.file_hex}`}>
                        <td><small>{++num}</small></td>
                        <td><small>{item.file_name}</small></td>
                        <td className="text-right">
                            <small>{this.formaterInt.format(item.file_size)}</small>
                        </td>
                        <td><small>{fileLoaded}</small></td>
                        <td>
                            <input 
                                type="checkbox" 
                                defaultChecked={item.file_loaded}
                                disabled={item.file_loaded}
                                onClick={this.handlerEvantsCheckbox.bind(this, { 
                                    fileName: item.file_name,
                                    fileSize: item.file_size,    
                                })}/>
                        </td>
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

        let sizeAllDownloadFile = () => {
            let num = 0;
            this.state.listFile.forEach((item) => {
                num += item.file_size;
            });

            return num;
        };

        return (
            <React.Fragment>
                <Row className="text-left text-muted pt-2">
                    <Col md={3}>
                        <small>всего файлов: </small>
                    </Col>
                    <Col md={9}>
                        <small>
                            <span className="text-info">{this.state.fullSizeListFile}</span> шт. 
                            (<span className="text-info">{this.formaterInt.format(sizeAllDownloadFile())}</span> байт)                            
                        </small>
                    </Col>
                </Row>
                <Row className="text-left text-muted mt-n2">
                    <Col md={3}>
                        <small>выбрано для скачивания: </small>
                    </Col>
                    <Col md={9}>
                        <small>
                            <span className="text-info">{this.state.numFileChecked}</span> шт. 
                            (<span className="text-info">{this.formaterInt.format(this.state.sizeFileChecked)}</span> байт)                            
                        </small>
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
                id="modal_window_list_download_file"
                size="lg"
                show={this.props.show} 
                onHide={this.props.onHide}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>{`Выгрузка файлов, источник №${this.props.shortTaskInfo.sourceID} (${this.props.shortTaskInfo.sourceName}).`}</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Row>
                        <Col md={12} className="text-right">
                            <Button 
                                className="mr-2"
                                variant="outline-secondary" 
                                onClick={this.handlerDownloadMarkerFiles} 
                                size="sm"
                                disabled={!this.props.userPermissionImport} >
                                скачать выбранное
                            </Button>
                            <Button 
                                variant="outline-primary" 
                                onClick={this.handlerDownloadAllFiles}
                                size="sm"
                                disabled={!this.props.userPermissionImport} >
                                скачать всё
                            </Button>
                        </Col>
                    </Row>
                    {this.createModalBody.call(this)}
                </Modal.Body>
                <Modal.Footer>
                    {this.buttonNext()}
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowListTaskDownloadFiles.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    socketIo: PropTypes.object.isRequired,
    shortTaskInfo: PropTypes.object.isRequired,
    userPermissionImport: PropTypes.bool.isRequired,
};