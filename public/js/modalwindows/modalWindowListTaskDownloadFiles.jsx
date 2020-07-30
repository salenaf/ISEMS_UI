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
            onScrollChunk: 0,
        };

        this.myRef = React.createRef();

        this.formaterInt = new Intl.NumberFormat();

        this.countAndSizeFileChecked = this.countAndSizeFileChecked.bind(this);
        this.handlerDownloadAllFiles = this.handlerDownloadAllFiles.bind(this);
        this.handlerDownloadMarkerFiles = this.handlerDownloadMarkerFiles.bind(this);

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

                let onScrollChunk = this.state.onScrollChunk + 1;

                let listFile = [].concat(this.state.listFile, msg.options.lf);

                this.setState({
                    taskID: msg.options.tid,
                    fullSizeListFile: msg.options.fls,
                    listFile: listFile,
                    listFileChecked: new Map,
                    numFileChecked: 0,
                    sizeFileChecked: 0,
                    onScrollChunk: onScrollChunk,
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
        console.log("func 'handlerDownloadAllFiles'");
        
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
        console.log("func 'handlerDownloadMarkerFiles'");

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

    onScroll() {
        if(this.state.listFile.size === this.state.fullSizeListFile){
            return;
        }

        //        const scrollY = window.scrollY; //Don't get confused by what's scrolling - It's not the window
        const scrollTop = this.myRef.current.scrollTop;

        console.log(`scrollTop: '${scrollTop}' > this.state.onScrollChunk * 227: '${this.state.onScrollChunk * 227}'`);

        if(scrollTop > (this.state.onScrollChunk * 227)){
            console.log(`onScroll, window.scrollY: ${scrollY} myRef.scrollTop: ${scrollTop}`);
            /*
ВОТ ЗДЕСь НЕ ПОНЯТНО, через какое то время генерируется
слишком много запросов

            здесь делаем запрос следующей части списка файлов,
            принимая следующую часть списка увеличиваем this.state.onScrollChunk 
            на 1 и добавляем список в массив listFile
            */
            this.props.socketIo.emit("network interaction: get a list of files for a task", {
                arguments: { 
                    taskID: this.state.taskID,
                    partSize: 25,
                    offsetListParts: this.state.onScrollChunk*25,
                } 
            });
        }

    }

    /**
     * Обработчики на кнопки 'скачать выбранное' 'скачать все' я
     * сделал, надо лишь протестировать, но не на этих
     * данных. Нужно все чистить и фильтровать заново.
     * Кроме того поиск работатет странно, задач найдено больше чем надо,
     * даже те по которым файлы уже были скачаны.
     * 
     * Еще необходим журнал событий модуля сетевого взаимодействия.
     * 
     * Сделать обработчик на подгрузку данных при скроле.
     */

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
                    <Col md={12} ref={this.myRef}
                        onScroll={this.onScroll.bind(this)}
                        style={{
                            //border: '1px solid black',
                            //width: "600px",
                            height: "800px",
                            overflow: "scroll",
                        }}>
                        <Table onScroll={this.handlerSrollFileList} size="sm" striped hover>
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
                        <div id="table_finish"></div>
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
                        <h5>{`Скачивание файлов, источник №${this.props.shortTaskInfo.sourceID} (${this.props.shortTaskInfo.sourceName}).`}</h5>
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
                <Modal.Footer></Modal.Footer>
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