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

    getListSource(){

        console.log("func 'getListSource', create source list...");

        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID) => {
            let isDisabled = !(this.props.listSources[sourceID].connectStatus);          

            return (
                <option 
                    key={`key_sour_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} 
                    disabled={isDisabled} >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }

    render(){
        return (
            <Form.Group>
                <Form.Control onChange={this.props.handlerChosen} as="select" size="sm" id="dropdown_list_sources">
                    <option></option>
                    {this.getListSource()}
                </Form.Control>
            </Form.Group>
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
            inputFieldIsValid: false,
            inputFieldIsInvalid: false,
            showDirectionAndButton: false,           
            inputRadioType: "any",
        };

        this.handlerInput = this.handlerInput.bind(this);
        this.checkRadioInput = this.checkRadioInput.bind(this);
        this.addPortNetworkIP = this.addPortNetworkIP.bind(this);
    }
    
    addPortNetworkIP(){
        if(this.state.typeValueInput === "none"){
            return;
        }

        this.props.addPortNetworkIP({
            "typeValueInput": this.state.typeValueInput,
            "inputRadioType": this.state.inputRadioType,
            "valueInput": this.state.valueInput,
        });

        this.setState({
            "inputFieldIsValid": false,
            "inputFieldIsInvalid": false,
        });

        document.getElementById("input_ip_network_port").value = "";
    }

    checkRadioInput(e){
        this.setState({ inputRadioType: e.target.value });
    }

    handlerInput(e){
        let value = e.target.value;

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
                        typeValueInput: "nw",
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
                if(helpers.checkInputValidation({
                    "name": "ipaddress", 
                    "value": value, 
                })){                  
                    this.setState({
                        inputFieldIsValid: true,
                        inputFieldIsInvalid: false,
                        valueInput: value,
                        typeValueInput: "ip",
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
        } else {
            if(helpers.checkInputValidation({
                "name": "port", 
                "value": value, 
            })){
                this.setState({
                    inputFieldIsValid: true,
                    inputFieldIsInvalid: false,
                    valueInput: value,
                    typeValueInput: "pt",
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

    listInputValue(){
        let isEmpty = true;

        done: 
        for(let et in this.props.inputValue){
            for(let d in this.props.inputValue[et]){
                if(this.props.inputValue[et][d].length > 0){
                    isEmpty = false;

                    break done;
                }
            }
        }

        if(isEmpty){
            return <React.Fragment></React.Fragment>;
        }

        let getList = (type) => {
            let getListDirection = (d) => {
                if(this.props.inputValue[type][d].length === 0){
                    return { value: "", success: false };
                }

                let result = this.props.inputValue[type][d].map((item) => {
                    if(d === "src"){
                        return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                            <small className="text-info">{d}&#8592; </small>{item}
                                &nbsp;<a onClick={this.props.delAddedElem.bind(this, {
                                type: type,
                                direction: d,
                                value: item
                            })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                        </div>; 
                    }
                    if(d === "dst"){
                        return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                            <small className="text-info">{d}&#8594; </small>{item}
                                &nbsp;<a onClick={this.props.delAddedElem.bind(this, {
                                type: type,
                                direction: d,
                                value: item
                            })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                        </div>; 
                    }

                    return <div className="ml-4" key={`elem_${type}_${d}_${item}`}>
                        <small className="text-info">{d}&#8596; </small>{item}
                            &nbsp;<a onClick={this.props.delAddedElem.bind(this, {
                            type: type,
                            direction: d,
                            value: item
                        })} className="clickable_icon" href="#"><img src="../images/icons8-delete-16.png"></img></a>
                    </div>; 
                });

                return { value: result, success: true };
            };

            let resultAny = getListDirection("any");
            let resultSrc = getListDirection("src");
            let resultDst = getListDirection("dst");

            return (
                <React.Fragment>
                    <div>{resultAny.value}</div>
                    {(resultAny.success && (resultSrc.success || resultDst.success)) ? <div className="text-danger text-center">&laquo;ИЛИ&raquo;</div> : <div></div>}                   
                    <div>{resultSrc.value}</div>
                    {(resultSrc.success && resultDst.success) ? <div className="text-danger text-center">&laquo;И&raquo;</div> : <div></div>}                   
                    <div>{resultDst.value}</div>
                </React.Fragment>
            );
        };

        return (
            <React.Fragment>
                <Row>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">ip адрес</Badge>
                    </Col>
                    <Col sm="1" className="text-danger text-center">&laquo;ИЛИ&raquo;</Col>
                    <Col sm="3" className="text-center">
                        <Badge variant="dark">сеть</Badge>
                    </Col>
                    <Col sm="1" className="text-danger text-center">&laquo;И&raquo;</Col>
                    <Col sm="4" className="text-center">
                        <Badge  variant="dark">сетевой порт</Badge>
                    </Col>
                </Row>
                <Row>
                    <Col sm="4">{getList("ip")}</Col>
                    <Col sm="4">{getList("nw")}</Col>
                    <Col sm="4">{getList("pt")}</Col>
                </Row>
            </React.Fragment>
        );
    }

    render(){
        if(!this.props.showMainFields){
            return <React.Fragment></React.Fragment>;
        }

        return (
            <React.Fragment>
                <Row className="mt-2">
                    <Col sm="3" className="text-right">
                        <small className="mr-1">сетевой протокол</small>
                        <CreateProtocolList handlerChosen={this.props.handlerChosenProtocol} />
                    </Col>
                    <Col sm="1"></Col>
                    <Col sm="4">
                        <small className="mr-1">начальное время</small>
                        <DatePicker 
                            className="form-control form-control-sm green-border"
                            selected={this.props.startDate}
                            onChange={this.props.handleChangeStartDate}
                            maxDate={new Date()}
                            showTimeInput
                            selectsStart
                            isClearable
                            timeFormat="p"
                            timeInputLabel="Time:"
                            dateFormat="dd.MM.yyyy hh:mm aa" />
                    </Col>
                    <Col sm="4">
                        <small className="mr-1">конечное время</small>
                        <DatePicker 
                            className="form-control form-control-sm red-border"
                            selected={this.props.endDate}
                            onChange={this.props.handleChangeEndDate}
                            maxDate={new Date()}
                            showTimeInput
                            selectsEnd
                            isClearable
                            timeFormat="p"
                            timeInputLabel="Time:"
                            dateFormat="dd.MM.yyyy hh:mm aa" />
                    </Col>
                </Row>
                <Row className="mt-3">
                    <Col className="text-center" sm="4">
                        <Form inline>
                            <Form.Check onClick={this.checkRadioInput} custom type="radio" id="r_direction_any" value="any" label="any" className="mt-1 ml-3" name="choseNwType" defaultChecked />
                            <Form.Check onClick={this.checkRadioInput} custom type="radio" id="r_direction_src" value="src" label="src" className="mt-1 ml-3" name="choseNwType" />
                            <Form.Check onClick={this.checkRadioInput} custom type="radio" id="r_direction_dst" value="dst" label="dst" className="mt-1 ml-3" name="choseNwType" />
                        </Form>
                    </Col>
                    <Col sm="8">
                        <InputGroup className="mb-3" size="sm">
                            <FormControl
                                id="input_ip_network_port"
                                aria-describedby="basic-addon2"
                                onChange={this.handlerInput}
                                isValid={this.state.inputFieldIsValid}
                                isInvalid={this.state.inputFieldIsInvalid} 
                                placeholder="введите ip адрес, подсеть или сетевой порт" />
                            <InputGroup.Append>
                                <Button onClick={this.addPortNetworkIP} variant="outline-secondary">
                                    добавить
                                </Button>
                            </InputGroup.Append>
                        </InputGroup>
                    </Col>
                </Row>
                {this.listInputValue.call(this)}
            </React.Fragment>
        );
    }
}

CreateMainFields.propTypes = {
    showMainFields: PropTypes.bool.isRequired,
    startDate: PropTypes.instanceOf(Date),
    endDate: PropTypes.instanceOf(Date),
    inputValue: PropTypes.object.isRequired,
    delAddedElem: PropTypes.func.isRequired,
    addPortNetworkIP: PropTypes.func.isRequired,
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
            inputValue: {
                ip: { any: [], src: [], dst: [] },
                pt: { any: [], src: [], dst: [] },
                nw: { any: [], src: [], dst: [] },
            },
        };

        this.windowClose = this.windowClose.bind(this);
        this.delAddedElem = this.delAddedElem.bind(this);
        this.addPortNetworkIP = this.addPortNetworkIP.bind(this);
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
            inputValue: {
                ip: { any: [], src: [], dst: [] },
                pt: { any: [], src: [], dst: [] },
                nw: { any: [], src: [], dst: [] },
            },
        });

        this.props.onHide();
    }

    addPortNetworkIP(objAdd){
        let objUpdate = Object.assign({}, this.state);
        if(Array.isArray(objUpdate.inputValue[objAdd.typeValueInput][objAdd.inputRadioType])){
            if(objUpdate.inputValue[objAdd.typeValueInput][objAdd.inputRadioType].includes(objAdd.valueInput)){
                return;
            }

            objUpdate.inputValue[objAdd.typeValueInput][objAdd.inputRadioType].push(objAdd.valueInput);

            this.setState(objUpdate);
        }
    }

    delAddedElem(objDel){
        let objUpdate = Object.assign({}, this.state);
        if(Array.isArray(objUpdate.inputValue[objDel.type][objDel.direction])){
            let list = objUpdate.inputValue[objDel.type][objDel.direction];
            objUpdate.inputValue[objDel.type][objDel.direction] = list.filter((item) => (item !== objDel.value));

            this.setState(objUpdate);
        }
    }

    handlerButtonSubmit(){

        console.log("func 'handlerButtonSubmit'");
        console.log(`networkProtocol: ${this.state.networkProtocol}`);

        this.props.handlerButtonSubmit({
            source: this.state.source,
            startDate: this.state.startDate,
            endDate: this.state.endDate,
            networkProtocol: this.state.networkProtocol,
            inputValue: this.state.inputValue,
        });

        this.windowClose();
    }

    handlerChosenSource(e){
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
        this.setState({
            networkProtocol: e.target.value
        });
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
                        <h5>Фильтрация сетевого трафика</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <CreateSourceList 
                        listSources={this.props.listSources}
                        handlerChosen={this.handlerChosenSource} />
                    <CreateMainFields
                        showMainFields={this.state.showMainFields}
                        startDate={this.state.startDate}
                        endDate={this.state.endDate}
                        inputValue={this.state.inputValue}
                        delAddedElem={this.delAddedElem}
                        addPortNetworkIP={this.addPortNetworkIP}
                        handleChangeStartDate={this.handleChangeStartDate}
                        handleChangeEndDate={this.handleChangeEndDate}
                        handlerChosenProtocol={this.handlerChosenProtocol} />
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-secondary" onClick={this.windowClose} size="sm">
                        закрыть
                    </Button>
                    <Button variant="outline-primary" onClick={this.handlerButtonSubmit} size="sm">
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