"use strict";

import React from "react";
import {  Badge, Button, Col, Row, InputGroup, Form, FormControl, Modal } from "react-bootstrap";
import PropTypes from "prop-types";

import DatePicker from "react-datepicker";

import { helpers } from "../common_helpers/helpers.js";

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

CreateSourceList.propTypes = {
    listSources: PropTypes.object.isRequired,
    handlerChosen: PropTypes.func.isRequired,
};

class CreateMainFields extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            typeValueInput: "none",
            valueInput: "",
            showDirectionAndButton: false,
            inputFieldIsValid: false,
            inputFieldIsInvalid: false,
        };

        this.handlerInput = this.handlerInput.bind(this);
    }
    
    createDirectionAndButton(){
        if(!this.state.showDirectionAndButton){
            return <Col sm="6"></Col>;
        }

        return (
            <Form>
                <Col sm="6">
                    <Form.Check custom type="radio" id="r_direction_any" label="any" defaultChecked />
                    <Form.Check custom type="radio" id="r_direction_src" label="src" />
                    <Form.Check custom type="radio" id="r_direction_dst" label="dst" />
                    
                    {this.state.typeValueInput /**только для теста*/}
                </Col>
            </Form>
        );
    }

    handlerInput(e){
        let value = e.target.value;

        console.log(`handler input: ${value}`);



        if(value.includes(".")){
            if(value.includes("/")){
                if(helpers.checkInputValidation({
                    "name": "network", 
                    "value": value, 
                })){    
                    this.setState({
                        inputFieldIsValid: true,
                        inputFieldIsInvalid: false,
                        valueInput: value,
                        typeValueInput: "network",
                    });
                } else {  
                    this.setState({
                        inputFieldIsValid: false,
                        inputFieldIsInvalid: true,
                        valueInput: "",
                        typeValueInput: "none",
                    });
                }
            } else {
                console.log("IP");

                if(helpers.checkInputValidation({
                    "name": "ipaddress", 
                    "value": value, 
                })){
                    console.log("IP VALID");
                    
                    this.setState({
                        inputFieldIsValid: true,
                        inputFieldIsInvalid: false,
                        valueInput: value,
                        typeValueInput: "ip",
                    });
                } else {  
                    console.log("IP INVALID");

                    this.setState({
                        inputFieldIsValid: false,
                        inputFieldIsInvalid: true,
                        valueInput: "",
                        typeValueInput: "none",
                    });
                }
            }
        } else {
            if(helpers.checkInputValidation({
                "name": "port", 
                "value": value, 
            })){
                this.setState({
                    inputFieldIsValid: true,
                    inputFieldIsInvalid: false,
                    valueInput: value,
                    typeValueInput: "port",
                });
            } else {
                this.setState({
                    inputFieldIsValid: false,
                    inputFieldIsInvalid: true,
                    valueInput: "",
                    typeValueInput: "none",
                });
            }
        }

        this.setState({
            showDirectionAndButton: true,
        });
    }

    render(){
        if(!this.props.showMainFields){
            return <React.Fragment></React.Fragment>;
        }

        return (
            <React.Fragment>
                <Row className="mt-2">
                    <Col sm="4">
                        <small className="mr-1">начальное время</small>
                        <DatePicker 
                            className="form-control form-control-sm green-border"
                            selected={this.props.startDate}
                            onChange={this.props.handleChangeStartDate}
                            maxDate={new Date()}
                            showTimeSelect
                            selectsStart
                            isClearable
                            timeFormat="p"
                            timeIntervals={5}
                            timeCaption="time"
                            dateFormat="dd.MM.yyyy hh:mm aa" />
                    </Col>
                    <Col sm="4">
                        <small className="mr-1">конечное время</small>
                        <DatePicker 
                            className="form-control form-control-sm red-border"
                            selected={this.props.endDate}
                            onChange={this.props.handleChangeEndDate}
                            maxDate={new Date()}
                            showTimeSelect
                            selectsEnd
                            isClearable
                            timeFormat="p"
                            timeIntervals={5}
                            timeCaption="time"
                            dateFormat="dd.MM.yyyy hh:mm aa" />
                    </Col>
                    <Col sm="1"></Col>
                    <Col sm="3" className="text-right">
                        <small className="mr-1">сетевой протокол</small>
                        <CreateProtocolList handlerChosen={this.props.handlerChosenProtocol} />
                    </Col>
                </Row>
                <Row className="mt-2">
                    <Col sm="6">
                        <InputGroup size="sm">
                            <FormControl 
                                id="input_value" 
                                onChange={this.handlerInput}
                                isValid={this.state.inputFieldIsValid}
                                isInvalid={this.state.inputFieldIsInvalid} 
                                placeholder="введите ip адрес, сетевой порт или подсеть" />
                        </InputGroup>
                    </Col>
                    {this.createDirectionAndButton.call(this)}
                </Row>
            </React.Fragment>
        );
    }
}

CreateMainFields.propTypes = {
    showMainFields: PropTypes.bool.isRequired,
    startDate: PropTypes.instanceOf(Date),
    endDate: PropTypes.instanceOf(Date),
    handleChangeStartDate: PropTypes.func.isRequired,
    handleChangeEndDate: PropTypes.func.isRequired,
    handlerChosenProtocol: PropTypes.func.isRequired,
};

export default class ModalWindowAddFilteringTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showMainFields: false,
            source: 0,
            startDate: new Date(),
            endDate: new Date(),
            networkProtocol: "any",
        };

        this.windowClose = this.windowClose.bind(this);
        this.handlerButtonSubmit = this.handlerButtonSubmit.bind(this);
        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handleChangeStartDate = this.handleChangeStartDate.bind(this);
        this.handleChangeEndDate = this.handleChangeEndDate.bind(this);
        this.handlerChosenProtocol = this.handlerChosenProtocol.bind(this);
    }

    windowClose(){
        this.setState({
            showMainFields: false,
            source: 0,
            startDate: new Date(),
            endDate: new Date(),
            networkProtocol: "any",
        });

        this.props.onHide();
    }

    handlerButtonSubmit(){
        this.props.handlerButtonSubmit({
            startDate: this.state.startDate,
            endDate: this.state.endDate,
            networkProtocol: this.state.networkProtocol,
        });
    }

    handlerChosenSource(e){
        console.log("func 'handlerChosenSource', START...");
        console.log(`chosen source: ${e.target.value}`);

        this.setState({
            showMainFields: true,
            source: +(e.target.value),
        });
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

    handlerChosenProtocol(e){
        console.log("func 'handlerChosenProtocol', START...");
        console.log(`chosen protocol: ${e.target.value}`);

        this.setState({
            networkProtocol: e.target.value
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
                    <Row className="mt-2">
                        <Col sm="12">
                            <CreateSourceList 
                                listSources={this.props.listSources}
                                handlerChosen={this.handlerChosenSource} />                        
                        </Col>
                    </Row>
                    <CreateMainFields
                        showMainFields={this.state.showMainFields}
                        startDate={this.state.startDate}
                        endDate={this.state.endDate}
                        handleChangeStartDate={this.handleChangeStartDate}
                        handleChangeEndDate={this.handleChangeEndDate}
                        handlerChosenProtocol={this.handlerChosenProtocol}
                    />
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-secondary" onClick={this.windowClose} size="sm">
                        закрыть
                    </Button>
                    <Button variant="outline-primary" onClick={this.props.handlerButtonSubmit} size="sm">
                        отправить
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
};