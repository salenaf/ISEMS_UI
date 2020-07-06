"use strict";

import React from "react";
import { Badge, Button, Col, Modal, Row, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

/**
 * Типовое модальное окно для  вывода всей информации о выполняемой задаче
 * Сначала выводится вся информация о задаче полученная по запросу из БД,
 * а по мере обновления информации и перехватывания соответсвующих событий
 * обновляется только информация относящаяся к данному событию
 */
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

        this.getList = this.getList.bind(this);

        this.handlerEvents.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (msg) => {
            if(msg.type === "processingGetAllInformationByTaskID"){
                
                console.log(msg.options);

                /**
 * заполнить объект состояния
 */

                this.setState({
                    showInfo: true,
                    parametersFiltration: msg.options.taskParameter.fo,
                    filteringStatus: {
                        dateCreateTask: msg.options.taskParameter.diof.tte.s*1000,
                        dateFinishTask: msg.options.taskParameter.diof.tte.e*1000,
                    },
                    downloadingStatus: {}
                });
            }
        });
    }

    getList(type){
        let getListDirection = (d) => {
            if(this.state.parametersFiltration.f[type][d].length === 0){
                return { value: "", success: false };
            }

            let result = this.state.parametersFiltration.f[type][d].map((item) => {
                if(d === "src"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8592; {item}</small>
                    </div>); 
                }
                if(d === "dst"){
                    return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8594; {item}</small>
                    </div>); 
                }

                return (<div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                    <small className="text-info">{d}&#8596; {item}</small>
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
                {(resultAny.success && (resultSrc.success || resultDst.success)) ? <div className="text-danger text-center">&laquo;<small>ИЛИ</small>&raquo;</div> : <div></div>}                   
                <div>{resultSrc.value}</div>
                {(resultSrc.success && resultDst.success) ? <div className="text-danger text-center">&laquo;<small>И</small>&raquo;</div> : <div></div>}                   
                <div>{resultDst.value}</div>
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
                    <Col sm="1" className="text-danger text-center">&laquo;<small>ИЛИ</small>&raquo;</Col>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">сеть</Badge>
                    </Col>
                    <Col sm="1" className="text-danger text-center">&laquo;<small>И</small>&raquo;</Col>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">сетевой порт</Badge>
                    </Col>
                </Row>
                <Row>
                    <Col sm="4">{this.getList("ip")}</Col>
                    <Col sm="4">{this.getList("nw")}</Col>
                    <Col sm="4">{this.getList("pt")}</Col>
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

        return (
            <React.Fragment>
                <Row>
                    <Col className="text-center">
                    Задача по фильтрации (добавлена: <i>{formatter.format(this.state.dateCreateTask)}</i>, завершена: <i>{formatter.format(this.state.dateFinishTask)}</i>)
                    </Col>
                </Row>
                <Row>
                    <Col sm="9" className="mt-0 text-muted">
                        <small>
                            дата и время
                            начальное: <strong>{formatter.format(dts)}</strong>, 
                            конечное: <strong>{formatter.format(dte)}</strong>
                        </small>
                    </Col>
                    <Col sm="3" className="mt-0 text-muted"><small>сетевой протокол: <strong>{(this.state.parametersFiltration.p === "any") ? "любой" : this.state.parametersFiltration.p}</strong></small></Col>
                </Row>
                <Row><Col sm="12">{this.createNetworkParameters.call(this)}</Col></Row>
                <Row>
                    <Col sm="6" className="text-muted">
                        <small>параметры</small>
                    </Col>
                    <Col sm="6" className="text-muted">
                        <small>ход выполнения</small>
                    </Col>
                </Row>
                <Row>
                    <Col className="text-center">
                    Задача по скачиванию файлов (добавлена: <i>{formatter.format(this.state.dateCreateTask)}</i>, завершена: <i>{formatter.format(this.state.dateFinishTask)}</i>)
                    </Col>
                </Row>
            </React.Fragment>
        );
    }

    /**
 * Доделать модальное окно
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