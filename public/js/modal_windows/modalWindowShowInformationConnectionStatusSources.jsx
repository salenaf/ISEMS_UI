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

    createGroup(){
        let formatterDate = new Intl.DateTimeFormat("ru-Ru", {
            timeZone: "Europe/Moscow",
            day: "numeric",
            month: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "numeric",
        });

        let list = [];
        let sourceList = this.props.sourceList;
        for(let sid in sourceList){
            let connectStatus = (sourceList[sid].connectStatus) ? "my_circle_green" : "my_circle_red";
            let dateTime = " не определено";
            let ct = sourceList[sid].connectTime;
            
            if(ct !== 0 && (ct+"").length < 12){
                dateTime = formatterDate.format(sourceList[sid].connectTime*1000);
            }

            list.push(<Row key={`key_${sid}`} className="mt-n2 mb-n2 ml-3 mr-3 text-muted">
                <Col md={7} className="text-left">
                    <canvas className={connectStatus}></canvas>
                        &emsp;{`${sid} ${sourceList[sid].shortName} `}
                </Col>
                <Col md={5} className="text-right">
                    <i>{dateTime}</i>
                </Col>
            </Row>);
        }

        return list;
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
                        <Col>{this.createGroup.call(this)}</Col>
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