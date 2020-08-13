"use strict";

import React from "react";
import {  Badge, Button, Col, Row, InputGroup, Form, FormControl, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

import { networkCal } from "../common_helpers/networkCalc.js";

export default class ModalWindowLanCalc extends React.Component {
    constructor(props){
        super(props);

        this.state = {};

        this.windowClose = this.windowClose.bind(this);
    }

    windowClose(){
        this.props.onHide();
    }

    render(){       
        return (
            <Modal
                id="modal_create_task_filter"
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Сетевой калькулятор</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Row>
                        <Col sm={12}>
                            <InputGroup className="mb-3">
                                <FormControl
                                    size="sm"
                                    placeholder="ip адрес" />
                                <InputGroup.Append>
                                    <Button 
                                        variant="outline-secondary"
                                        size="sm" >
                                    рассчитать
                                    </Button>
                                </InputGroup.Append>
                            </InputGroup>
                        </Col>
                    </Row>
                    <Row>
                        <Col sm={12}>
                        здесь будет результат подсчета
                        </Col>
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

/**
 *   
 * Это из flashlight что бы не разбираться что использовать
 *       
        let ip4Address = new IPv4_Address(valueNetwork, valueNetworkMask);
        let countIpAddress = (parseFloat(ip4Address.netbcastInteger) - parseFloat(ip4Address.netaddressInteger) + 1);

        let divResult = '<div class="col-sm-3 col-md-3 col-lg-3"></div><div class="col-sm-4 col-md-4 col-lg-4 text-center"><strong>string</strong></div><div class="col-sm-5 col-md-5 col-lg-5 text-center"><strong>integer</strong></div>';
        divResult += `<div class="col-sm-3 col-md-3 col-lg-3">ip-address</div><div class="col-sm-4 col-md-4 col-lg-4 text-center">${valueNetwork}</div><div class="col-sm-5 col-md-5 col-lg-5 text-center">${ip4Address.addressInteger}</div>`;
        divResult += `<div class="col-sm-3 col-md-3 col-lg-3">network</div><div class="col-sm-4 col-md-4 col-lg-4 text-center">${ip4Address.netaddressDotQuad}</div><div class="col-sm-5 col-md-5 col-lg-5 text-center">${ip4Address.netaddressInteger}</div>`;
        divResult += `<div class="col-sm-3 col-md-3 col-lg-3">broadcast</div><div class="col-sm-4 col-md-4 col-lg-4 text-center">${ip4Address.netbcastDotQuad}</div><div class="col-sm-5 col-md-5 col-lg-5 text-center">${ip4Address.netbcastInteger}</div>`;
        divResult += `<div class="col-md-12"><strong>количество ip-адресов: ${countIpAddress}</strong></div>`;
 */

ModalWindowLanCalc.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
};