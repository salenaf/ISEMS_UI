"use strict";

import React from "react";
import { Badge, Button, Card, Col, Modal, Row, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

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

        this.getListNetworkParameters = this.getListNetworkParameters.bind(this);
        this.getInformationProgressFiltration = this.getInformationProgressFiltration.bind(this);

        this.handlerEvents.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {
            if(msg.type === "processingGetAllInformationByTaskID"){
                
                console.log(msg.options);

                this.setState({
                    showInfo: true,
                    parametersFiltration: msg.options.taskParameter.fo,
                    filteringStatus: msg.options.taskParameter.diof,
                    downloadingStatus: msg.options.taskParameter.diod,
                });
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
        let taskStatus = "";
        let ts = this.state.filteringStatus.ts;
        var formatter = new Intl.NumberFormat("ru");

        if(ts === "wait"){
            taskStatus = <small className="text-info">готовится к выполнению</small>;
        }
        if(ts === "refused"){
            taskStatus = <small className="text-danger">oтклонена</small>;
        }
        if(ts === "execute"){
            taskStatus = <small className="text-primary">выполняется</small>;
        }
        if(ts === "complete"){
            taskStatus = <small className="text-success">завершена успешно</small>;
        }
        if(ts === "stop"){
            taskStatus = <small className="text-warning">остановлена пользователем</small>;
        }

        return (
            <React.Fragment>
                <Row className="mb-n2">
                    <Col md={6}><small>статус задачи:</small></Col>
                    <Col md={6} className="text-center">{taskStatus}</Col>
                </Row>
                <Row className="mb-n2">
                    <Col md={6}><small>всего файлов:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.nfmfp}</strong> шт.</small></Col>
                </Row>
                <Row className="mb-n2">
                    <Col md={6}><small>общим размером:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{formatter.format(this.state.filteringStatus.sfmfp)}</strong> байт</small></Col>
                </Row>
                <Row className="mb-n2">
                    <Col md={6}><small>файлов обработанно:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.mpf}</strong> шт.</small></Col>
                </Row>
                <Row className="mb-n2">
                    <Col md={6}><small>файлов найдено:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.nffrf}</strong> шт.</small></Col>
                </Row>
                <Row className="mb-n2">
                    <Col md={6}><small>общим размером:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{formatter.format(this.state.filteringStatus.sffrf)}</strong> байт</small></Col>
                </Row>
                <Row>
                    <Col md={6}><small>фильтруемых директорий:</small></Col>
                    <Col md={6} className="text-right"><small><strong>{this.state.filteringStatus.ndf}</strong> шт.</small></Col>
                </Row>
            </React.Fragment>
        );
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

        let dts = this.state.parametersFiltration.dt.s*1000;
        let dte = this.state.parametersFiltration.dt.e*1000;

        console.log(this.state.filteringStatus);

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-center">
                    Задача по фильтрации (добавлена: <i>{formatter.format(this.state.filteringStatus.tte.s*1000)}</i>, завершена: <i>{formatter.format(this.state.filteringStatus.tte.e*1000)}</i>)
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
                                начальное: <strong>{formatter.format(dts)}</strong>, 
                                конечное: <strong>{formatter.format(dte)}</strong>
                                </small>
                            </Col>
                            <Col md={3} className="text-muted"><small>сетевой протокол: <strong>{(this.state.parametersFiltration.p === "any") ? "любой" : this.state.parametersFiltration.p}</strong></small></Col>
                        </Row>
                        <Row><Col md={12}>{this.createNetworkParameters.call(this)}</Col></Row>
                    </Card.Body>                   
                </Card>               
                <Row>
                    <Col md={12} className="text-muted mt-3">
                        <small>ход выполнения</small>
                    </Col>
                </Row>
                <Row>
                    <Col md={8} className="text-muted">
                        <Card>
                            <Card.Body className="pt-0 pb-0">{this.getInformationProgressFiltration()}</Card.Body>
                        </Card>
                    </Col>
                    <Col md={4} className="mt-0 text-muted">график</Col>
                </Row>
                <Row className="text-center text-muted">
                    <Col md={12}>
                        <small>директория содержащая файлы полученные в результате фильтрации</small>
                    </Col>
                    <Col md={12} className="mt-n2">
                        <small><strong>{this.state.filteringStatus.pdfff}</strong></small>
                    </Col>
                </Row>
                <Row>
                    <Col md={12} className="text-center mt-3">
                    Задача по скачиванию файлов (добавлена: <i>{formatter.format(this.state.dateCreateTask)}</i>, завершена: <i>{formatter.format(this.state.dateFinishTask)}</i>)
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