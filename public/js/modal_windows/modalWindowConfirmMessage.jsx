"use strict";

import React from "react";
import { Alert, Modal, Button } from "react-bootstrap";
import PropTypes from "prop-types";

class ModalWindowConfirmMessage extends React.Component {
    constructor(props){
        super(props);

        this.handlerClose = this.handlerClose.bind(this);
        this.handlerConfirm = this.handlerConfirm.bind(this);
        this.showAlertMessage = this.showAlertMessage.bind(this);
    }

    handlerClose(){
        this.props.onHide();    
    }

    handlerConfirm(){
        this.props.handlerConfirm(this.props.nameDel);
        handlerClose();
    }

    showAlertMessage(){
        if((typeof this.props.showAlert !== "undefined") && this.props.showAlert){
            return (
                <Alert variant="danger">
                    <p>{this.props.alertMessage.header}</p>
                    <p>{this.props.alertMessage.msg}</p>
                </Alert>
            );
        }
    }
/*centered*/
    render(){
        return (
            <Modal show={this.props.show} onHide={this.handlerClose} >
                <Modal.Header closeButton>
                    <Modal.Title>{this.props.msgTitle}</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    {this.props.msgBody}
                    {this.showAlertMessage()}
                </Modal.Body>
                <Modal.Footer>
                    <Button size="sm" variant="outline-secondary" onClick={this.handlerClose}>Отмена</Button>
                    <Button size="sm" variant="outline-primary" onClick={this.handlerConfirm}>Подтвердить</Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowConfirmMessage.propTypes = {
    show: PropTypes.bool.isRequired,
    onHide: PropTypes.func.isRequired,
    showAlert: PropTypes.bool,
    alertMessage: PropTypes.object,
    msgBody: PropTypes.string.isRequired,
    msgTitle: PropTypes.string.isRequired,
    nameDel: PropTypes.string.isRequired,
    handlerConfirm: PropTypes.func.isRequired,
};

export {ModalWindowConfirmMessage};