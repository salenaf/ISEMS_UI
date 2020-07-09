"use strict";

import React from "react";
import { Badge, Button, Card, Col, Modal, Row, Spinner, ProgressBar } from "react-bootstrap";
import PropTypes from "prop-types";

import Circle from "react-circle";

/**
 * Типовое модальное окно для вывода всей информации о выполняемой задаче
 * Сначала выводится вся информация о задаче полученная по запросу из БД,
 * а по мере обновления информации и перехватывания соответсвующих событий
 * обновляется только информация относящаяся к данному событию
 */
export default class ModalWindowShowTaskFiltraion extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showInfo: false,
            taskID: "",
            userTimeCreateTask: 0,
            userNameCreateTask: "",
            userCreateTaskType: "",
            parametersFiltration: {
                dt: {s:0, e:0},
                f: {
                    ip: { any: [], src: [], dst: [] },
                    nw: { any: [], src: [], dst: [] },
                    pt: { any: [], src: [], dst: [] },
                },
                p: "any",
            },
            filteringStatus: {
                mpf: 0, ndf: 0, nepf: 0, nffrf: 0, nfmfp: 0, sffrf: 0, sfmfp: 0, ts: "нет данных",
                tte: { s: 0, e: 0},
            },
            downloadingStatus: {
                nfd: 0, nfde: 0, nft: 0, pdsdf: "", ts: "нет данных",
                tte: { s: 0, e: 0},
            }
        };

        this.formatter = Intl.DateTimeFormat("ru-Ru", {
            timeZone: "Europe/Moscow",
            day: "numeric",
            month: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "numeric",
        });

        this.getListNetworkParameters = this.getListNetworkParameters.bind(this);
        this.getInformationProgressFiltration = this.getInformationProgressFiltration.bind(this);

        this.handlerEvents.call(this);
    }

    testProgressBar(){
        /*
        console.log(`before: ${this.state.filteringStatus.mpf}`);

        let copy = Object.assign(this.state.filteringStatus);
        copy.mpf = 0;
        this.setState({filteringStatus: copy});

        console.log(`after ${this.state.filteringStatus.mpf}`);
*/
        let numInterval = 0;
        let timerID = setInterval(() => {
            if(numInterval === (this.state.filteringStatus.mpf - 1)){
                clearInterval(timerID);
            }

            let copy = Object.assign(this.state.filteringStatus);
            copy.mpf = numInterval++;
            this.setState({filteringStatus: copy});
        }, 3000);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {
            if(msg.type === "processingGetAllInformationByTaskID"){

                console.log(msg.options);

                this.setState({
                    showInfo: true,
                    taskID: msg.options.taskParameter.tid,
                    userTimeCreateTask: (msg.options.createDate !== 0) ? this.formatter.format(msg.options.createDate): "нет данных",
                    userNameCreateTask: msg.options.userName,
                    userCreateTaskType: msg.options.typeTask,
                    parametersFiltration: msg.options.taskParameter.fo,
                    filteringStatus: msg.options.taskParameter.diof,
                    downloadingStatus: msg.options.taskParameter.diod,
                });
            }
            if(msg.type === "filtrationProcessing"){
                console.log(msg.options);

                if(this.state.taskID !== msg.options.taskIDModuleNI){
                    return;
                }

                let tmpCopy = Object.assign(this.state.filteringStatus);
                tmpCopy.nfmfp = msg.options.parameters.numAllFiles;
                tmpCopy.nffrf = msg.options.parameters.numFindFiles;
                tmpCopy.mpf = msg.options.parameters.numProcessedFiles;
                tmpCopy.nepf = msg.options.parameters.numProcessedFilesError;
                tmpCopy.sfmfp = msg.options.parameters.sizeAllFiles;
                tmpCopy.sffrf = msg.options.parameters.sizeFindFiles;
                tmpCopy.ts = msg.options.status;
                this.setState({ filteringStatus: tmpCopy });
            }
        });
    }

    getListNetworkParameters(type){
        let getListDirection = (d) => {
            if(this.state.parametersFiltration.f[type][d].length === 0){
                return { value: "", success: false };
            }

            let result = this.state.parametersFiltration.f[type][d].map((item) => {
                if(d === "src"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8592; </small><small>{item}</small>
                    </div>); 
                }
                if(d === "dst"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8594; </small><small>{item}</small>
                    </div>); 
                }

                return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                    <small className="text-info">{d}&#8596; </small><small>{item}</small>
                </div>); 
            });

            return { value: result, success: true };
        };

        let resultAny = getListDirection("any");
        let resultSrc = getListDirection("src");
        let resultDst = getListDirection("dst");

        return (
            <React.Fragment>
                <div>{resultAny.value}</div>
                {(resultAny.success && (resultSrc.success || resultDst.success)) ? <div className="text-danger text-center my-n2">&laquo;<small>ИЛИ</small>&raquo;</div> : <div></div>}                   
                <div>{resultSrc.value}</div>
                {(resultSrc.success && resultDst.success) ? <div className="text-danger text-center  my-n2">&laquo;<small>И</small>&raquo;</div> : <div></div>}                   
                <div>{resultDst.value}</div>
            </React.Fragment>
        );
    }

    getInformationProgressFiltration(){
        if(this.state.filteringStatus.nfmfp === 0){
            return;
        }

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-muted mt-0">
                        <small>ход выполнения</small>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-muted">
                        <Card>
                            <Card.Body className="pt-0 pb-0">
                                <Row>
                                    <Col md={8} className="text-muted">                                
                                        <Row className="mb-n2">
                                            <Col md={6}><small>всего файлов:</small></Col>
                                            <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.nfmfp}</strong> шт.</small></Col>
                                        </Row>
                                        <Row className="mb-n2">
                                            <Col md={6}><small>общим размером:</small></Col>
                                            <Col md={6} className="text-right"><small><strong>{this.formatter.format(this.state.filteringStatus.sfmfp)}</strong> байт</small></Col>
                                        </Row>
                                        <Row className="mb-n2">
                                            <Col md={6}><small>файлов обработанно:</small></Col>
                                            <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.mpf}</strong> шт.</small></Col>
                                        </Row>
                                        <Row className="mb-n2">
                                            <Col md={6}><small>файлов обработанно с ошибкой:</small></Col>
                                            <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.nepf}</strong> шт.</small></Col>
                                        </Row>
                                        <Row className="mb-n2">
                                            <Col md={6}><small>файлов найдено:</small></Col>
                                            <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.nffrf}</strong> шт.</small></Col>
                                        </Row>
                                        <Row className="mb-n2">
                                            <Col md={6}><small>общим размером:</small></Col>
                                            <Col md={6} className="text-right"><small><strong>{this.formatter.format(this.state.filteringStatus.sffrf)}</strong> байт</small></Col>
                                        </Row>
                                        <Row>
                                            <Col md={6}><small>фильтруемых директорий:</small></Col>
                                            <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.ndf}</strong> шт.</small></Col>
                                        </Row>
                                    </Col>
                                    <Col md={4} className="mt-3 text-center">
                                        {this.createCircleProcessFilter.call(this)}
                                    </Col>
                                </Row>
                            </Card.Body>
                        </Card>
                    </Col>
                </Row>
            </React.Fragment>
        );
    }

    getInformationProgressDownload(){
    /**
    // NumberFilesTotal - общее количество файлов подлежащих скачиванию
// NumberFilesDownloaded - количество уже загруженных файлов
// NumberFilesDownloadedError - количество файлов загруженных с ошибкой
     */

        if(this.state.filteringStatus.nffrf === 0){
            return;
        }

        let percent = Math.round((this.state.downloadingStatus.nfd*100) / this.state.downloadingStatus.nft);

        return (<React.Fragment>
            <Row>
                <Col md={12} className="text-muted">
                    <small>
                        общее количество файлов подлежащих скачиванию: <strong>{this.state.downloadingStatus.nft}</strong>, 
                        загруженных файлов: <strong>{this.state.downloadingStatus.nfd}</strong>, 
                        из них с ошибкой: <strong>{this.state.downloadingStatus.nfde}</strong>
                    </small>
                </Col>
            </Row>
            <Row>
                <Col md={12}>
                    <ProgressBar now={percent} label={`${percent}%`} />
                </Col>
            </Row>
        </React.Fragment>);
    }

    getStatusFiltering(){
        let ts = this.state.filteringStatus.ts;
    
        if(ts === "wait"){
            return <small className="text-info">готовится к выполнению</small>;
        } else if(ts === "refused"){
            return <small className="text-danger">oтклонена</small>;
        } else if(ts === "execute"){
            return <small className="text-primary">выполняется</small>;
        } else if(ts === "complete"){
            return <small className="text-success">завершена успешно</small>;
        } else if(ts === "stop"){
            return <small className="text-warning">остановлена пользователем</small>;
        } else {
            return <small>ts</small>;
        }
    }

    getStatusDownload(){
        let ts = this.state.downloadingStatus.ts;
    
        if(ts === "wait"){
            return <small className="text-info">готовится к выполнению</small>;
        } else if(ts === "refused"){
            return <small className="text-danger">oтклонена</small>;
        } else if(ts === "execute"){
            return <small className="text-primary">выполняется</small>;       
        } else if(ts === "complete"){
            return <small className="text-success">завершена успешно</small>;       
        } else if(ts === "stop"){
            return <small className="text-warning">остановлена пользователем</small>;
        } else if(ts === "not executed"){
            return <small className="text-light bg-dark">не выполнялась</small>;
        } else {
            return <small>ts</small>;
        }
    }

    createNetworkParameters(){
        return (
            <React.Fragment>
                <Row>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">ip адрес</Badge>
                    </Col>
                    <Col sm="2" className="text-danger text-center">&laquo;<small>ИЛИ</small>&raquo;</Col>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">сеть</Badge>
                    </Col>
                    <Col sm="1" className="text-danger text-center">&laquo;<small>И</small>&raquo;</Col>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">сетевой порт</Badge>
                    </Col>
                </Row>
                <Row>
                    <Col sm="4">{this.getListNetworkParameters("ip")}</Col>
                    <Col sm="1"></Col>
                    <Col sm="4">{this.getListNetworkParameters("nw")}</Col>
                    <Col sm="3">{this.getListNetworkParameters("pt")}</Col>
                </Row>
            </React.Fragment>
        );
    }

    createCircleProcessFilter() {
        let percent = (this.state.filteringStatus.mpf*100) / this.state.filteringStatus.nfmfp;

        return (<Circle
            progress={Math.round(percent)}
            animate={true} // Boolean: Animated/Static progress
            animationDuration="1s" // String: Length of animation
            responsive={false} // Boolean: Make SVG adapt to parent size
            size="125" // String: Defines the size of the circle.
            lineWidth="35" // String: Defines the thickness of the circle's stroke.
            progressColor="rgb(76, 154, 255)" // String: Color of "progress" portion of circle.
            bgColor="#ecedf0" // String: Color of "empty" portion of circle.
            textColor="#6b778c" // String: Color of percentage text color.
            textStyle={{
                font: "bold 4rem Helvetica, Arial, sans-serif" // CSSProperties: Custom styling for percentage.
            }}
            percentSpacing={10} // Number: Adjust spacing of "%" symbol and number.
            roundedStroke={false} // Boolean: Rounded/Flat line ends
            showPercentage={true} // Boolean: Show/hide percentage.
            showPercentageSymbol={true} // Boolean: Show/hide only the "%" symbol.
        />);
    }

    createPathDirFilterFiles(){
        if(this.state.filteringStatus.nfmfp === 0){
            return;
        }

        return (<Row className="text-center text-muted">                   
            <Col md={12}>
                <small>директория содержащая файлы полученные в результате фильтрации</small>
            </Col>
            <Col md={12} className="mt-n2">
                <small><strong>{this.state.filteringStatus.pdfff}</strong></small>
            </Col>
        </Row>);
    }

    createPathDirStorageFiles(){
        if(this.state.downloadingStatus.nfd === 0){
            return;
        }

        return (<Row className="text-center text-muted">                   
            <Col md={12}>
                <small>директория для долговременного хранения загруженных файлов</small>
            </Col>
            <Col md={12} className="my-n2 py-m2">
                <small><strong>{this.state.downloadingStatus.pdsdf}</strong></small>
            </Col>
        </Row>);
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

        let fdts = this.state.parametersFiltration.dt.s*1000;
        let fdte = this.state.parametersFiltration.dt.e*1000;

        let filtrationStart = this.state.filteringStatus.tte.s*1000;
        if(filtrationStart === 0){
            filtrationStart = "нет данных";
        } else {
            filtrationStart = this.formatter.format(filtrationStart);
        }

        let filtrationEnd = this.state.filteringStatus.tte.e*1000;
        if(filtrationEnd === 0){
            filtrationEnd = "нет данных";
        } else {
            filtrationEnd = this.formatter.format(filtrationEnd);
        }

        let downloadStart = this.state.downloadingStatus.tte.s*1000;
        if(downloadStart === 0){
            downloadStart = "нет данных";
        } else {
            downloadStart = this.formatter.format(downloadStart);
        }

        let downloadEnd = this.state.downloadingStatus.tte.e*1000;
        if(downloadEnd === 0){
            downloadEnd = "нет данных";
        } else {
            downloadEnd = this.formatter.format(downloadEnd);
        }

        return (
            <React.Fragment>
                <Row className="text-muted text-center">
                    <Col md={12}>
                        <small>Пользователь: <strong>{this.state.userNameCreateTask}</strong> добавил задачу по <strong>{this.state.userCreateTaskType}</strong> в <strong>{this.state.userTimeCreateTask}</strong></small>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-center">
                    Задача по фильтрации (добавлена: <i>{filtrationStart}</i>, завершена: <i>{filtrationEnd}</i>)
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-muted mt-2">
                        <small>параметры</small>
                    </Col>
                </Row>
                <Card>
                    <Card.Body className="pt-0 pb-0">
                        <Row>
                            <Col md={9} className="text-muted">
                                <small>
                                дата и время,
                                начальное: <strong>{this.formatter.format(fdts)}</strong>, 
                                конечное: <strong>{this.formatter.format(fdte)}</strong>
                                </small>
                            </Col>
                            <Col md={3} className="text-muted"><small>сетевой протокол: <strong>{(this.state.parametersFiltration.p === "any") ? "любой" : this.state.parametersFiltration.p}</strong></small></Col>
                        </Row>
                        <Row><Col md={12}>{this.createNetworkParameters.call(this)}</Col></Row>
                    </Card.Body>                   
                </Card>               
                <Row className="text-muted mb-n2">
                    <Col md={2}><small>статус задачи: </small></Col>
                    <Col md={10} className="text-center">{this.getStatusFiltering.call(this)}</Col>
                </Row>
                {this.getInformationProgressFiltration()}
                {this.createPathDirFilterFiles.call(this)}
                <Row>
                    <Col md={12} className="text-center mt-3">
                    Задача по скачиванию файлов (добавлена: <i>{downloadStart}</i>, завершена: <i>{downloadEnd}</i>)
                    </Col>
                </Row>
                <Row className="text-muted mb-n2">
                    <Col md={2}><small>статус задачи: </small></Col>
                    <Col md={10} className="text-center">{this.getStatusDownload.call(this)}</Col>
                </Row>
                {this.getInformationProgressDownload.call(this)}
                {this.createPathDirStorageFiles.call(this)}
            </React.Fragment>
        );
    }

    /**
 * Сделать отслеживание хода выполнения скачивания файлов как
 * в модальном окне так и на основной странице.
 * Сделать обработчик для кнопки "остановить задачу" в модальном окне
 * 
 */

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