"use strict";

import React from "react";
import {  Button, Col, Row, Form, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

export default class ModalWindowEncodeDecoder extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            decodeType: "uri",
            inputDecode: "",
            inputEncode: "",
            errorMessage: "",
        };

        this.windowClose = this.windowClose.bind(this);
        this.handlerButtonDecode = this.handlerButtonDecode.bind(this);
        this.handlerButtonEncode = this.handlerButtonEncode.bind(this);
        this.hendlerChoseDecodeType = this.hendlerChoseDecodeType.bind(this);
        this.handlerChangeInputDecode = this.handlerChangeInputDecode.bind(this);
        this.handlerChangeInputEncode = this.handlerChangeInputEncode.bind(this);
    }

    windowClose(){
        this.props.onHide();
    }

    hendlerChoseDecodeType(e){
        console.log("func 'hendlerChoseDecodeType'");
        console.log(e.target.value);

        this.setState({ decodeType: e.target.value });

    }

    handlerChangeInputDecode(e){
        console.log("func 'handlerChangeInputDecode'");
        console.log(e.target.value);
        
        this.setState({ inputDecode: e.target.value });
    }

    handlerChangeInputEncode(e){
        console.log("func 'handlerChangeInputEncode'");
        console.log(e.target.value);

        this.setState({ inputEncode: e.target.value });
    }

    handlerButtonDecode(){
        console.log("func 'handlerButtonDecode'");

        switch(this.state.decodeType){
        case "uri":
            this.setState({ inputEncode: decodeURI(this.state.inputDecode) });

            break;
        case "base64":
            try {
                this.setState({ inputEncode: atob(this.state.inputDecode) });
            } catch(e) {
                this.setState({ errorMessage: "Ошибка, недопустимые символы" });
            }    
    
            break;
        case "hex":
            break;

        case "qp":
            break;
        }
    }

    handlerButtonEncode(){
        console.log("func 'handlerButtonEncode'");

        switch(this.state.decodeType){
        case "uri":
            this.setState({ inputDecode: encodeURI(this.state.inputEncode) });

            break;
        case "base64":
            try {
                this.setState({ inputDecode: btoa(this.state.inputEncode) });
            } catch(e) {
                this.setState({ errorMessage: "Ошибка, допустимы только латинские символы" });
            }
            break;
        case "hex":
            break;

        case "qp":
            break;
        }
    }

    render(){       
        return (
            <Modal
                id="modal_create_task_filter"
                size="xl"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Набор декодировщиков</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Row>
                        <Col md={2}>
                            <Form className="mt-4">
                                <Form.Check onClick={this.hendlerChoseDecodeType} type="radio" value="uri" label="URI" name="choseType" className="ml-3" defaultChecked />
                                <Form.Check onClick={this.hendlerChoseDecodeType} type="radio" value="base64" label="Base64" name="choseType" className="ml-3" />
                                <Form.Check onClick={this.hendlerChoseDecodeType} type="radio" value="hex" label="Hex" name="choseType" className="ml-3" />
                                <Form.Check onClick={this.hendlerChoseDecodeType} type="radio" value="qp" label="Quoted Printable" name="choseType" className="ml-3" />
                            </Form>
                        </Col>
                        <Col md={10}>
                            <Row>
                                <Col md={6}><small className="text-muted">Декодирование</small></Col>
                                <Col md={6}><small className="text-muted">Кодирование</small></Col>
                            </Row>
                            <Row>
                                <Col md={6}>                                  
                                    <Form.Control 
                                        value={this.state.inputDecode}
                                        onChange={this.handlerChangeInputDecode}
                                        as="textarea" 
                                        rows={6} />
                                </Col>
                                <Col md={6}>
                                    <Form.Control 
                                        value={this.state.inputEncode}
                                        onChange={this.handlerChangeInputEncode}
                                        as="textarea"
                                        rows={6} />
                                </Col>
                            </Row>
                            <Row>
                                <Col md={6} className="mt-3 text-right">
                                    <Button 
                                        variant="outline-primary" 
                                        onClick={this.handlerButtonDecode}
                                        size="sm">
                                        декодирование
                                    </Button>
                                </Col>
                                <Col md={6} className="mt-3 text-right">
                                    <Button 
                                        variant="outline-primary" 
                                        onClick={this.handlerButtonEncode}
                                        size="sm">
                                        кодирование
                                    </Button>
                                </Col>
                            </Row>
                            <Row>
                                <Col md={12}>
                                    <small className="text-danger">{this.state.errorMessage}</small>
                                </Col>
                            </Row>
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

ModalWindowEncodeDecoder.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
};