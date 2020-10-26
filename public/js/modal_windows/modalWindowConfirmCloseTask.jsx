/**
 * Модуль формирования модального окна для дольнейшего
 * подтверждения или отклонения действия по Закрытию
 * задачи
 * 
 * Версия 0.1 дата релиза 23.10.2020
 */

"use strict";

import React from "react";
import { Button, Col, Row, Modal, Form } from "react-bootstrap";
import PropTypes from "prop-types";

class ModalWindowConfirmCloseTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            description: "",
        };

        this.handlerClose = this.handlerClose.bind(this);
        this.handlerConfirm = this.handlerConfirm.bind(this);
    }

    handlerClose(){
        this.props.onHide();    
    }

    handlerConfirm(){
        this.props.handlerConfirm({
            taskID: this.props.commonParameters.taskID,
            description: this.state.description,
        });
    }

    handlerInput(e){
        this.setState({ description: e.target.value });
    }

    render(){
        return (
            <Modal show={this.props.show} onHide={this.handlerClose}>
                <Modal.Header closeButton>
                    <span className="text-muted">Закрыть задачу</span>
                </Modal.Header>
                <Modal.Body>
                    <Row>
                        <Col md={12} className="text-center">Вы действительно хотите закрыть задачу с ID <i className="text-info">{this.props.commonParameters.taskID}</i>?</Col>
                    </Row>
                    <Row className="mt-2">
                        <Col md={12}>
                            <Form.Group>
                                <Form.Label className="text-muted">примечание</Form.Label>
                                <Form.Control 
                                    as="textarea" 
                                    id="description" 
                                    rows="2"
                                    onChange={this.handlerInput.bind(this)} />
                            </Form.Group>
                        </Col>
                    </Row>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-secondary" onClick={this.handlerClose}>отмена</Button>
                    <Button variant="outline-primary" onClick={this.handlerConfirm}>подтвердить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowConfirmCloseTask.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    commonParameters: PropTypes.object.isRequired,
    handlerConfirm: PropTypes.func.isRequired,
};

export {ModalWindowConfirmCloseTask};