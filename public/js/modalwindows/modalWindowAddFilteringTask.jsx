"use strict";

import React from "react";
import { Accordion, Badge, Button, Card, Col, Row, Form, Modal, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

import DatePicker from "react-datepicker";

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

        this.state = {
            startDate: new Date(),
            endDate: new Date(),
        };

        this.windowClose = this.windowClose.bind(this);
        this.handleChangeStartDate = this.handleChangeStartDate.bind(this);
        this.handleChangeEndDate = this.handleChangeEndDate.bind(this);
    }

    windowClose(){
        this.props.onHide();
    }

    handleChangeStartDate(date){
        this.setState({
            startDate: date
        });
    }

    handleChangeEndDate(date){
        this.setState({
            endDate: date
        });
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
                    <Row className="text-center">
                        <Col sm="6">
                            <small className="mr-1">начальное время</small>
                            <DatePicker 
                                className="form-control form-control-sm green-border"
                                selected={this.state.startDate}
                                onChange={this.handleChangeStartDate}
                                maxDate={new Date()}
                                showTimeSelect
                                selectsStart
                                isClearable
                                timeFormat="p"
                                timeIntervals={5}
                                timeCaption="time"
                                dateFormat="dd.MM.yyyy hh:mm aa" />
                        </Col>
                        <Col sm="6">
                            <small className="mr-1">конечное время</small>
                            <DatePicker 
                                className="form-control form-control-sm red-border"
                                selected={this.state.endDate}
                                onChange={this.handleChangeEndDate}
                                maxDate={new Date()}
                                selectsEnd
                                isClearable
                                timeFormat="p"
                                timeIntervals={5}
                                timeCaption="time"
                                dateFormat="dd.MM.yyyy hh:mm aa" />
                        </Col>
                    </Row>
                    <Row className="mt-2">
                        <Col sm="8">
                            <CreateSourceList 
                                listSources={this.props.listSources}
                                handlerChosen={this.props.handlerChosenSource} />                        
                        </Col>
                        <Col sm="2" className="text-right">
                            <small className="mr-1">сет. протокол</small>
                        </Col>
                        <Col sm="2">
                            <CreateProtocolList handlerChosen={this.props.handlerChosenProtocol} />
                        </Col>
                    </Row>
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-primary" onClick={this.props.handlerButtonSubmit} size="sm">
                        отправить
                    </Button>
                    <Button variant="outline-secondary" onClick={this.windowClose} size="sm">
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