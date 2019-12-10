/**
 * Модуль формирования модального окна для дольнейшего
 * подтверждения или отклонения действия по УДАЛЕНИЮ
 * 
 * Версия 0.1. дата релиза 10.12.2019
 */

"use strict";

import React from "react";
import { Modal, Button } from "react-bootstrap";
import PropTypes from "prop-types";

export {ModalWindowConfirmMessage};

class ModalWindowConfirmMessage extends React.Component {
    constructor(props){
        super(props);

        this.handlerClose = this.handlerClose.bind(this);
        this.handlerConfirm = this.handlerConfirm.bind(this);
    }

    handlerClose(){
        this.props.onHide();    
    }

    handlerConfirm(){
        this.props.handlerConfirm(this.props.userID);
    }

    render(){
        return (
            <Modal show={this.props.show} onHide={this.handlerClose}>
                <Modal.Header closeButton>
                    <Modal.Title>{this.props.msgTitle}</Modal.Title>
                </Modal.Header>
                <Modal.Body>{this.props.msgBody}</Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-secondary" onClick={this.handlerClose}>отмена</Button>
                    <Button variant="outline-primary" onClick={this.handlerConfirm}>подтвердить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowConfirmMessage.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    msgBody: PropTypes.string.isRequired,
    msgTitle: PropTypes.string.isRequired,
    userID: PropTypes.string.isRequired,
    handlerConfirm: PropTypes.func.isRequired,
};