"use strict";

import React from "react";
import { Modal, Button } from "react-bootstrap";
import PropTypes from "prop-types";

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
        this.props.handlerConfirm(this.props.nameDel);
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
    nameDel: PropTypes.string.isRequired,
    handlerConfirm: PropTypes.func.isRequired,
};

export {ModalWindowConfirmMessage};