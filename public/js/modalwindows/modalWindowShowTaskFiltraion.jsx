"use strict";

import React from "react";
import { Button, Col, Modal, Row, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowShowTaskFiltraion extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            sourceID: this.props.shortTaskInfo.sourceID,
            sourceName: this.props.shortTaskInfo.sourceName,
            dateCreateTask: +(new Date), //так только для теста

        };
    }

    render(){
        let formatter = Intl.DateTimeFormat("ru-Ru", {
            timeZone: "Europe/Moscow",
            day: "numeric",
            month: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "numeric",
        });

        /**
 * 
 * Доделать модельное окно с информацией о выполняемой
 * задачи с расчетом что данное модальное окно будет
 * выводится еще и при поиске
 * 
 */

        return (
            <Modal
                size="lg"
                show={this.props.show} 
                onHide={this.props.onHide}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Источник №{this.state.sourceID} ({this.state.sourceName})</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Row>
                        <Col className="text-center mt-0 text-muted">
                            <small>задание добавлено {formatter.format(this.state.dateCreateTask)}</small>
                        </Col>
                    </Row>
                    <Row></Row>
                    <Row>
                        <Col sm="6">Параметры фильтрации</Col>
                        <Col sm="6">Ход выполнения фильтрации</Col>
                    </Row>

                    <div className="col-md-12 text-center">
                        <Spinner animation="border" role="status" variant="primary">
                            <span className="sr-only">Загрузка...</span>
                        </Spinner>
                    </div>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-danger" onClick={this.props.handlerButtonStopFiltering} size="sm">
                        отменить
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
};