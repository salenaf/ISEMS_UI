"use strict";

import React from "react";
import {  Button, Col, Row, Form, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

import utf8 from "utf8";
import quotedPrintable from "quoted-printable";

export default class ModalWindowEncodeDecoder extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            decodeType: "uri",
            inputDecode: "",
            inputEncode: "",
            errorMessage: "",
        };

        this.examples = {
            "uri": ["%D0%B4%D0%BE%D0%BA%D1%83%D0%BC%D0%B5%D0%BD%D1%82", "документ"],
            "base64": ["ZG9jdW1lbnQ=", "document"],
            "hex": ["\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74", "document"],
            "qp": ["=D0=B4=D0=BE=D0=BA=D1=83=D0=BC=D0=B5=D0=BD=D1=82", "документ"],
        };

        this.windowClose = this.windowClose.bind(this);
        this.handlerButtonDecode = this.handlerButtonDecode.bind(this);
        this.handlerButtonEncode = this.handlerButtonEncode.bind(this);
        this.hendlerChoseDecodeType = this.hendlerChoseDecodeType.bind(this);
        this.handlerChangeInputDecode = this.handlerChangeInputDecode.bind(this);
        this.handlerChangeInputEncode = this.handlerChangeInputEncode.bind(this);
    }

    windowClose(){
        this.setState({
            decodeType: "uri",
            inputDecode: "",
            inputEncode: "",
            errorMessage: "",
        });

        this.props.onHide();
    }

    hendlerChoseDecodeType(e){
        this.setState({ decodeType: e.target.value });

    }

    handlerChangeInputDecode(e){       
        this.setState({ inputDecode: e.target.value });
    }

    handlerChangeInputEncode(e){
        this.setState({ inputEncode: e.target.value });
    }

    handlerButtonDecode(){
        let decodeHex = () => {
            return this.state.inputDecode.replace(/\\x([0-9A-Fa-f]{2,4})/g, function() {      
                return String.fromCharCode(parseInt(arguments[1], 16));
            });
        };

        switch(this.state.decodeType){
        case "uri":
            this.setState({ inputEncode: decodeURI(this.state.inputDecode) });

            break;
        case "base64":
            try {
                this.setState({ inputEncode: atob(this.state.inputDecode) });
            } catch(e) {
                this.setState({ errorMessage: "Ошибка! Недопустимые символы." });
            }    
    
            break;
        case "hex":
            this.setState({ inputEncode: decodeHex() });

            break;

        case "qp":
            this.setState({ inputEncode: utf8.decode(quotedPrintable.decode(this.state.inputDecode)) });

            break;
        }
    }

    handlerButtonEncode(){
        let encodeHex = () => {
            let s = unescape(encodeURIComponent(this.state.inputEncode));
            let h = "";
            for (let i = 0; i < s.length; i++) {
                h += s.charCodeAt(i).toString(16);
            }

            return h;
        };

        switch(this.state.decodeType){
        case "uri":
            this.setState({ inputDecode: encodeURI(this.state.inputEncode) });

            break;
        case "base64":
            try {
                this.setState({ inputDecode: btoa(this.state.inputEncode) });
            } catch(e) {
                this.setState({ errorMessage: "Ошибка! Допустимы только латинские символы." });
            }
            break;
        case "hex":
            try {
                this.setState({ inputDecode: encodeHex() });
            } catch(e) {
                this.setState({ errorMessage: "Ошибка! Допустимы только латинские символы." });                
            }

            break;

        case "qp":
            this.setState({ inputDecode: quotedPrintable.encode(utf8.encode(this.state.inputEncode)) });

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
                                        декодировать
                                    </Button>
                                </Col>
                                <Col md={6} className="mt-3 text-right">
                                    <Button 
                                        variant="outline-primary" 
                                        onClick={this.handlerButtonEncode}
                                        size="sm">
                                        кодировать
                                    </Button>
                                </Col>
                            </Row>
                            <Row>
                                <Col md={12}>
                                    <small>
                                    пример: {this.examples[this.state.decodeType][0]} - {this.examples[this.state.decodeType][1]}
                                    </small>
                                </Col>
                            </Row>
                            <Row>
                                <Col md={12} className="text-center mt-2">
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