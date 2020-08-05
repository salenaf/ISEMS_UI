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

            /*if(msg.type !== "downloadProcessing" && msg.type !== "filtrationProcessing"){
                console.log(msg);
            }*/

            if(msg.type === "listFilesByTaskID"){
                //                console.log("--- received file list ---");
                //                console.log(msg.options);
                //                console.log("--------------------------");

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
                    listFileChecked: new Map,
                    numFileChecked: 0,
                    sizeFileChecked: 0,
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
        window.location.href = "network_interaction";
    }

    handlerDownloadMarkerFiles(){
        let fileList = [];
        for(let fn of this.state.listFileChecked.keys()){
            fileList.push(fn);
        }

        console.log("-- func 'handlerDownloadMarkerFiles' ---");
        console.log(`source id: '${this.props.shortTaskInfo.sourceID}'`);

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

    /**
 * Такое впечатление что при отправке 1 задачи на скачивание файлов
 * в ISEMS-NIH_master начинают выполнятся ТРИ, ОДНА выполняется,
 * а две отклоняются из-за того что имеют одинаковый taskID
 * 
 * Но судя по логам в api_client_requests.log ISEMS-NIH_master
 * запрос на скачивание файлов приходит один
 * 
 */

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

    /**
 * 1. Виджет загрузка файлов выполняется/доступна,
 * доступна не отображается (не 0 а просто ничего)
 * если нет задач по которым возможна выгрузка файлов.
 * 2. Кроме того нет автообновления вкладки 'загрузка файлов'
 * при выполении фильтрации, если были найдены файлы
 * необходимые к загрузке, а также нет автообновления
 * при завершении задачи по скачиванию файло (надо убрать ее
 * из списка задач для скачивания).
 * 3. Поиск во вкладке 'загрузка файлов' выдает слишком
 * много задач, в том числе и задачи по которым файлы выгружались.
 * 4. Если нет задач для скачивания файлов, то нотификатион
 * выводит информацию об этом при обновлении страницы.
 * 5. При выполнении скачивания части файлов, не обновляется модальное
 * окно со списком файлов возможных к загрузки.
 * 
 *          !!!!!
 * 6, Какого то хрена, при скачивании выбранных файлов в БД
 * ISEMS-NIH_master не меняется количество скаченных файлов.
 * (ОКАЗЫВАЕТСЯ ЭТО КОЛ-ВО ЗАГРУЖЕННЫХ ФАЙЛОВ ЗА ОДНУ ЗАДАЧУ,
 * ТО ЕСТЬ ВЫБРАЛ ДЛЯ ЗАГРУЗКИ 3 ФАЙЛА, 4 БЫЛО ЗАГРУЖЕНО). Зачем
 * я так сделал не знаю, но для поиска задач ФАЙЛЫ ПО КОТОРЫМ НЕ
 * БЫЛИ полностью загружены данный параметр не подходит.
 *  Наверное стоит переделать в ISEMS-NIH_master (или я ошибся где то)
 * и записывать параметр detailed_information_on_downloading.number_files_downloaded 
 * основываясь на подсчете загруженных файлов через список list_files_result_task_execution.
 */

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