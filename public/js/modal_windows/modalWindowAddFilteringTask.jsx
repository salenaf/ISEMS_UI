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
        let np = [
            {t:"any", n:"любой"},
            {t:"tcp", n:"tcp"},
            {t:"udp", n:"udp"},
        ];

        return (
            <select 
                disabled={this.props.isDisabled} 
                defaultValue={this.props.networkProtocol}
                className="custom-select custom-select-sm" 
                onChange={this.props.handlerChosen} 
                id="protocol_list">
                {np.map((item) => {
                    return <option key={`key_p_${item.t}`} value={item.t}>{item.n}</option>;
                })}

            </select>
        );
    }
}

CreateProtocolList.propTypes = {
    isDisabled: PropTypes.bool.isRequired,
    networkProtocol: PropTypes.string.isRequired,
    handlerChosen: PropTypes.func.isRequired,
};

class CreateSourceList extends React.Component {
    constructor(props){
        super(props);

        this.getListSource = this.getListSource.bind(this);
    }

    getListSource(){
        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID, num) => {
            let isDisabled = !(this.props.listSources[sourceID].connectStatus);          

            return (
                <option 
                    key={`key_source_${num}_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} 
                    disabled={isDisabled} >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }

    render(){
        let disabled = false;
        if(this.props.typeModal === "повторная"){
            if(this.props.hiddenFields){
                disabled = true;
            } else {              
                disabled = false;
            }
        }

        return (
            <Form.Group>
                <Form.Control 
                    disabled={disabled} 
                    onChange={this.props.handlerChosen} 
                    defaultValue={this.props.currentSource} 
                    as="select" 
                    size="sm" 
                    id="dropdown_list_sources" >
                    <option></option>
                    {this.getListSource()}
                </Form.Control>
            </Form.Group>
        );
    }
}

CreateSourceList.propTypes = {
    typeModal: PropTypes.string.isRequired,
    hiddenFields: PropTypes.bool.isRequired,
    listSources: PropTypes.object.isRequired,
    currentSource: PropTypes.number.isRequired,
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

        let disabled = false;
        if(this.props.typeModal === "повторная"){
            if(this.props.hiddenFields){
                disabled = true;
            } else {               
                disabled = false;
            }
        }

        let startDate = this.props.startDate;
        let endDate = this.props.endDate;
        if(disabled){
            if(+new Date(this.props.startDate) !== +(new Date(this.props.sd))){
                startDate = null;
            }

            if(+new Date(this.props.endDate) !== +(new Date(this.props.ed))){
                endDate = null;
            }
        }

        let formatterDate = new Intl.DateTimeFormat("ru-Ru", {
            timeZone: "Europe/Moscow",
            day: "numeric",
            month: "numeric",
            year: "numeric",
            hour: "numeric",
            minute: "numeric",
        });

        return (
            <React.Fragment>
                <Row className="mt-2">
                    <Col sm="3" className="text-right">
                        <small className="mr-1">сетевой протокол</small>
                        <CreateProtocolList 
                            isDisabled={disabled}
                            networkProtocol={this.props.networkProtocol} 
                            handlerChosen={this.props.handlerChosenProtocol} />
                    </Col>
                    <Col sm="1"></Col>
                    <Col sm="4">
                        <small className="mr-1">начальное время</small>
                        <DatePicker 
                            className="form-control form-control-sm green-border"
                            selected={startDate}
                            onChange={this.props.handlerChangeStartDate}
                            maxDate={new Date()}
                            disabled={disabled}
                            showTimeInput
                            selectsStart
                            isClearable
                            timeFormat="p"
                            timeInputLabel="Time:"
                            dateFormat="dd.MM.yyyy hh:mm aa"
                            placeholderText={formatterDate.format(this.props.sd)} />
                    </Col>
                    <Col sm="4">
                        <small className="mr-1">конечное время</small>
                        <DatePicker 
                            className="form-control form-control-sm red-border"
                            selected={endDate}
                            onChange={this.props.handlerChangeEndDate}
                            maxDate={new Date()}
                            disabled={disabled}
                            showTimeInput
                            selectsEnd
                            isClearable
                            timeFormat="p"
                            timeInputLabel="Time:"
                            dateFormat="dd.MM.yyyy hh:mm aa"
                            placeholderText={formatterDate.format(this.props.ed)} />
                    </Col>
                </Row>
                <Row className="mt-3">
                    <Col className="text-center" sm="4">
                        <Form inline>
                            <Form.Check onClick={this.checkRadioInput} custom type="radio" disabled={disabled} id="r_direction_any" value="any" label="any" className="mt-1 ml-3" name="choseNwType" defaultChecked />
                            <Form.Check onClick={this.checkRadioInput} custom type="radio" disabled={disabled} id="r_direction_src" value="src" label="src" className="mt-1 ml-3" name="choseNwType" />
                            <Form.Check onClick={this.checkRadioInput} custom type="radio" disabled={disabled} id="r_direction_dst" value="dst" label="dst" className="mt-1 ml-3" name="choseNwType" />
                        </Form>
                    </Col>
                    <Col sm="8">
                        <InputGroup className="mb-3" size="sm">
                            <FormControl
                                id="input_ip_network_port"
                                aria-describedby="basic-addon2"
                                onChange={this.handlerInput}
                                disabled={disabled}
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
    typeModal: PropTypes.string.isRequired,
    hiddenFields: PropTypes.bool.isRequired,
    showMainFields: PropTypes.bool.isRequired,
    startDate: PropTypes.instanceOf(Date),
    sd:PropTypes.instanceOf(Date),
    endDate: PropTypes.instanceOf(Date),
    ed:PropTypes.instanceOf(Date),
    inputValue: PropTypes.object.isRequired,
    networkProtocol: PropTypes.string.isRequired,
    delAddedElem: PropTypes.func.isRequired,
    addPortNetworkIP: PropTypes.func.isRequired,
    handlerChangeStartDate: PropTypes.func.isRequired,
    handlerChangeEndDate: PropTypes.func.isRequired,
    handlerChosenProtocol: PropTypes.func.isRequired,
};

export default class ModalWindowAddFilteringTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showMainFields: false,
            hiddenFields: true,
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
        this.handlerButtonChange = this.handlerButtonChange.bind(this);
        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handlerChangeStartDate = this.handlerChangeStartDate.bind(this);
        this.handlerChangeEndDate = this.handlerChangeEndDate.bind(this);
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
        this.setState({ hiddenFields: true });
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
        this.props.handlerButtonSubmit({
            source: this.state.source,
            startDate: this.state.startDate,
            endDate: this.state.endDate,
            networkProtocol: this.state.networkProtocol,
            inputValue: this.state.inputValue,
        });

        this.windowClose();
    }

    handlerButtonChange(){
        this.setState({ 
            hiddenFields: false,
            source: this.props.currentFilteringParameters.sid,
            startDate: new Date(this.props.currentFilteringParameters.dt.s*1000),
            endDate: new Date(this.props.currentFilteringParameters.dt.e*1000),
            networkProtocol: this.props.currentFilteringParameters.p,
            inputValue: this.props.currentFilteringParameters.f,
        });
    }

    handlerChosenSource(e){
        this.setState({
            showMainFields: true,
            source: +(e.target.value),
        });
    }

    handlerChangeStartDate(date){
        this.setState({ startDate: date });
    }

    handlerChangeEndDate(date){
        this.setState({ endDate: date });
    }

    handlerChosenProtocol(e){
        this.setState({
            networkProtocol: e.target.value
        });
    }

    render(){       
        let emitOnChange; 
        let tm = "новая";
        let showMainFields = this.state.showMainFields;
        let startDate = this.state.startDate;
        let sd = this.state.startDate;
        let endDate = this.state.endDate;
        let ed = this.state.endDate;
        let inputValue = this.state.inputValue;
        let networkProtocol = this.state.networkProtocol;
        let disabled = false;
        
        if(this.props.currentFilteringParameters.sid !== 0){
            tm = "повторная";
            emitOnChange = <Row>
                <Col md={12} className="text-right mt-2 mb-n1">
                    <span onClick={this.handlerButtonChange} className="text-info clicabe_cursor">
                        <u>изменить параметры фильтрации</u>
                    </span>
                </Col>
            </Row>;
            sd = new Date(this.props.currentFilteringParameters.dt.s*1000);
            ed = new Date(this.props.currentFilteringParameters.dt.e*1000);
            inputValue = this.props.currentFilteringParameters.f;
            networkProtocol = this.props.currentFilteringParameters.p;
            showMainFields = true;
            
            if(this.state.hiddenFields){
                disabled = true;
            } else {              
                disabled = false;
            }
        }

        return (
            <Modal
                id="modal_create_task_filter"
                size="lg"
                show={this.props.show} 
                onHide={this.windowClose}
                aria-labelledby="example-modal-sizes-title-lg" >
                <Modal.Header closeButton>
                    <Modal.Title id="example-modal-sizes-title-lg">
                        <h5>Фильтрация сетевого трафика ({tm})</h5>
                    </Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <CreateSourceList 
                        typeModal={tm}
                        hiddenFields={this.state.hiddenFields}
                        listSources={this.props.listSources}
                        currentSource={this.props.currentFilteringParameters.sid}
                        handlerChosen={this.handlerChosenSource} />
                    <CreateMainFields
                        typeModal={tm}
                        hiddenFields={this.state.hiddenFields}
                        showMainFields={showMainFields}
                        startDate={startDate}
                        sd={sd}
                        endDate={endDate}
                        ed={ed}
                        networkProtocol={networkProtocol}
                        inputValue={inputValue}
                        delAddedElem={this.delAddedElem}
                        addPortNetworkIP={this.addPortNetworkIP}
                        handlerChangeStartDate={this.handlerChangeStartDate}
                        handlerChangeEndDate={this.handlerChangeEndDate}
                        handlerChosenProtocol={this.handlerChosenProtocol} />
                    {emitOnChange}                    
                </Modal.Body>
                <Modal.Footer>
                    <Button variant="outline-secondary" onClick={this.windowClose} size="sm">
                        закрыть
                    </Button>
                    <Button variant="outline-primary" disabled={disabled} onClick={this.handlerButtonSubmit} size="sm">
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
    currentFilteringParameters: PropTypes.object.isRequired,
    handlerButtonSubmit: PropTypes.func.isRequired,
};