"use strict";

import React from "react";
import { Accordion, Badge, Button, Card, Col, Row, Form, Modal, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

class CreateProtocolList extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <select className="custom-select custom-select-sm" onChange={this.props.handlerChosen} id="protocol_list">
                <option value="any">любой</option>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
            </select>
        );
    }
}

CreateProtocolList.propTypes = {
    handlerChosen: PropTypes.func.isRequired,
};

class CreateSourceList extends React.Component {
    constructor(props){
        super(props);

        this.getListSource = this.getListSource.bind(this);
    }

    handlerDropDown(){
        this.el = $("#dropdown_sources");
       
        this.el.select2({
            placeholder: "выбор источника",
            containerCssClass: "input-group input-group-sm",
            width: "100%",
        });

        this.el.on("change", this.props.handlerChosen);
    }

    componentDidMount() {
        this.handlerDropDown.call(this);
    }

    getListSource(){
        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID) => {
            let isDisabled = !(this.props.listSources[sourceID].connectStatus);          
            return <option key={`key_sour_${this.props.listSources[sourceID].id}`} value={sourceID} disabled={isDisabled}>{`${sourceID} ${this.props.listSources[sourceID].shortName}`}</option>;
        });
    }

    render(){
        return (
            <select id="dropdown_sources">
                <option></option>
                {this.getListSource()}
            </select>
        );
    }
}

/**
 * Поставить и насторить bootstrapDatetimepicker
 * 
 * 
 */

CreateSourceList.propTypes = {
    listSources: PropTypes.object.isRequired,
    handlerChosen: PropTypes.func.isRequired,
};

export default class ModalWindowAddFilteringTask extends React.Component {
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
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Фильтрация сетевого трафика</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Form>
                        <Form.Group as={Row} controlId="formListSources">
                            <Col sm="2">источник</Col>
                            <Col sm="4" className="text-left">
                                <CreateSourceList 
                                    listSources={this.props.listSources}
                                    handlerChosen={this.props.handlerChosenSource} />
                            </Col>
                            <Col sm="2">протокол</Col>
                            <Col sm="2" className="text-left">
                                <CreateProtocolList handlerChosen={this.props.handlerChosenProtocol} />
                            </Col>
                            <Col sm="2"></Col>                            
                        </Form.Group>
                        <Form.Group as={Row} controlId="formListSources">
                            <Col sm="2"></Col>
                            <Col sm="10" className="text-left">
                            </Col>                            
                        </Form.Group>
                    </Form>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-primary" onClick={this.props.handlerButtonSubmit}>
                        отправить
                    </Button>
                    <Button variant="outline-secondary" onClick={this.windowClose}>
                        закрыть
                    </Button>
                </Modal.Footer>
            </Modal>
        );
    }
}

ModalWindowAddFilteringTask.propTypes = {
    show: PropTypes.bool,
    onHide: PropTypes.func,
    listSources: PropTypes.object.isRequired,
    handlerButtonSubmit: PropTypes.func.isRequired,
    handlerChosenSource: PropTypes.func.isRequired,
    handlerChosenProtocol: PropTypes.func.isRequired,
};