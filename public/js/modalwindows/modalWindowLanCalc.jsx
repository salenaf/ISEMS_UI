"use strict";

import React from "react";
import {  Badge, Button, Col, Row, InputGroup, Form, FormControl, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "../common_helpers/helpers.js";
import { IPv4_Address } from "../common_helpers/networkCalc.js";

export default class ModalWindowLanCalc extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            ipaddr: "",
            mask: 32,
            showResult: false,
            buttonDisabled: true,
            inputFieldIsValid: false,
            inputFieldIsInvalid: false,
            ipaddressConvertObject: {},
        };

        this.windowClose = this.windowClose.bind(this);
        this.handlerInput = this.handlerInput.bind(this);
        this.handlerChosenMask = this.handlerChosenMask.bind(this);
        this.handlerClickButton = this.handlerClickButton.bind(this);
    }

    windowClose(){
        this.setState({
            showResult: false,
            buttonDisabled: true,
            inputFieldIsValid: false,
            inputFieldIsInvalid: false,
            ipaddressConvertObject: {},
        });

        this.props.onHide();
    }

    handlerInput(e){
        let value = e.target.value;

        if(helpers.checkInputValidation({
            "name": "ipaddress", 
            "value": value, 
        })){                  
            this.setState({
                inputFieldIsValid: true,
                inputFieldIsInvalid: false,
                buttonDisabled: false,
                ipaddr: value,
                showResult: false,
                ipaddressConvertObject: {},
            });
        } else {
            this.setState({
                inputFieldIsValid: false,
                inputFieldIsInvalid: true,
                buttonDisabled: true,
                ipaddr: value,
                showResult: false,
            });
        }
    }

    handlerClickButton(){
        if(this.state.inputFieldIsInvalid){
            return;
        }

        this.setState({ 
            showResult: true,
            ipaddressConvertObject: new IPv4_Address(this.state.ipaddr, this.state.mask) 
        }); 
    }

    handlerChosenMask(e){
        this.setState({ mask: e.target.value });
    }

    createListMask(){
        let masks = [];
        for(let i = 1; i <=  32; i++){
            masks.push(
                <option 
                    key={`key_mask_${i}`} 
                    value={i} >
                    {i}    
                </option>
            );
        }

        masks.reverse();

        return (
            <Form.Group>
                <Form.Control 
                    as="select" 
                    size="sm"
                    onChange={this.handlerChosenMask} >
                    {masks}
                </Form.Control>
            </Form.Group>
        );
    }

    createCalculationResult(){
        if(!this.state.showResult){
            return <Row><Col sm={12}></Col></Row>;                    
        }

        return (
            <Row>
                <Col md={12}>
                    <Row>
                        <Col md={2} className="text-right"><Badge variant="primary">ipaddress</Badge></Col>
                        <Col md={2} className="text-left"><small>{this.state.ipaddr}</small></Col>
                        <Col md={8} className="text-left"><small>{this.state.ipaddressConvertObject.addressInteger}</small></Col>
                    </Row>
                    <Row>
                        <Col md={2} className="text-right"><Badge variant="dark">network</Badge></Col>
                        <Col md={2} className="text-left"><small>{this.state.ipaddressConvertObject.netaddressDotQuad}</small></Col>
                        <Col md={8} className="text-left"><small>{this.state.ipaddressConvertObject.netaddressInteger}</small></Col>
                    </Row>
                    <Row>
                        <Col md={2} className="text-right"><Badge variant="dark">broadcast</Badge></Col>
                        <Col md={2} className="text-left"><small>{this.state.ipaddressConvertObject.netbcastDotQuad}</small></Col>
                        <Col md={8} className="text-left"><small>{this.state.ipaddressConvertObject.netbcastInteger}</small></Col>
                    </Row>
                </Col>
            </Row>
        );
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
                        <Col md={2}>{this.createListMask.call(this)}</Col>
                        <Col sm={10}>
                            <InputGroup className="mb-3">
                                <FormControl
                                    size="sm"
                                    onChange={this.handlerInput}
                                    isValid={this.state.inputFieldIsValid}
                                    isInvalid={this.state.inputFieldIsInvalid} 
                                    placeholder="ip адрес" />
                                <InputGroup.Append>
                                    <Button 
                                        size="sm" 
                                        variant="outline-secondary"
                                        onClick={this.handlerClickButton}
                                        disabled={this.state.buttonDisabled} >
                                    рассчитать
                                    </Button>
                                </InputGroup.Append>
                            </InputGroup>
                        </Col>
                    </Row>
                    {this.createCalculationResult.call(this)}
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

ModalWindowLanCalc.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
};