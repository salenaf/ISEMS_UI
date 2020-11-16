"use strict";

import React from "react";
import {  Button, Col, Row, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowShowInformationConnectionStatusSources extends React.Component {
    constructor(props){
        super(props);

        this.windowClose = this.windowClose.bind(this);
    }

    windowClose(){
        this.props.onHide();
    }

    render(){       
        return (
            <Modal
                id="modal_show_info_connection_status"
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Статус соединения источников</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Row>
                        тут будет список источников
                        {this.props.sourceList}
                    </Row>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-secondary" onClick={this.windowClose} size="sm">
                        закрыть
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowShowInformationConnectionStatusSources.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
    sourceList: PropTypes.object.isRequired,
};