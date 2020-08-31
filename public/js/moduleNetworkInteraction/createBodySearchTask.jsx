import React from "react";
import { Button, Card, Col, Form, Row, FormControl, InputGroup } from "react-bootstrap";
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

export default class CreateBodySearchTask extends React.Component {
    constructor(props){
        super(props);

        this.getListSource = this.getListSource.bind(this);
        this.checkRadioInput = this.checkRadioInput.bind(this);
        this.handlerChosenProtocolList = this.handlerChosenProtocolList.bind(this);
    }

    handlerChosenProtocolList(){

    }

    checkRadioInput(){

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
            <React.Fragment>
                <Card className="mb-2" body>
                    <Form.Row>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.props.handlerChosen} as="select" size="sm" id="dropdown_list_sources">
                                <option>источник</option>
                                {this.getListSource()}
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control as="select" size="sm" id="dropdown_list_sources">
                                <option value="">статус фильтрации</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control as="select" size="sm" id="dropdown_list_sources">
                                <option value="">статус выгрузки файлов</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="not executed">не выполнялась</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col} controlId="formBasicCheckbox">
                            <Form.Check type="checkbox" label="только завершенные задачи" />
                        </Form.Group>
                    </Form.Row>
                    <Row>
                        <Col md={4} className="text-muted text-left">опции выгрузки файлов</Col>
                        <Col md={8} className="text-muted text-left">опции результатов фильтрации</Col>
                    </Row>
                    <Row>
                        <Col md={4}>
                            <Form.Group controlId="formBasicCheckbox">
                                <Form.Check type="checkbox" label="выгрузка выполнялась" />
                            </Form.Group>
                            <Form.Group controlId="formBasicCheckbox">
                                <Form.Check type="checkbox" label="все файлы выгружены" />
                            </Form.Group>
                        </Col>
                        <Col md={8}>
                            <Form.Row>
                                <Form.Group controlId="formBasicCheckbox">
                                    <Form.Check type="checkbox" label="были найдены файлы" />
                                </Form.Group>
                                <Form.Group as={Col} controlId="formGridEmail">
                                    <Form.Label>min кол-во файлов</Form.Label>
                                    <Form.Control type="input" placeholder="min кол-во файлов" />
                                </Form.Group>
                                <Form.Group as={Col} controlId="formGridEmail">
                                    <Form.Label>max кол-во файлов</Form.Label>
                                    <Form.Control type="input" placeholder="max кол-во файлов" />
                                </Form.Group>
                                <Form.Group as={Col} controlId="formGridEmail">
                                    <Form.Label>min размер файлов</Form.Label>
                                    <Form.Control type="input" placeholder="min кол-во файлов" />
                                </Form.Group>
                                <Form.Group as={Col} controlId="formGridEmail">
                                    <Form.Label>max размер файлов</Form.Label>
                                    <Form.Control type="input" placeholder="max кол-во файлов" />
                                </Form.Group>
                            </Form.Row>
                        </Col>
                    </Row>
                    <Row>
                        <Col md={12}>
                            <Col sm="3" className="text-right">
                                <small className="mr-1">сетевой протокол</small>
                                <CreateProtocolList handlerChosen={this.handlerChosenProtocolList} />
                            </Col>
                            <Col sm="1"></Col>
                            <Col sm="4">
                                <small className="mr-1">начальное время</small>
                                <DatePicker 
                                    className="form-control form-control-sm green-border"
                                    //selected={this.props.startDate}
                                    //onChange={this.props.handleChangeStartDate}
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
                                    //selected={this.props.endDate}
                                    //onChange={this.props.handleChangeEndDate}
                                    maxDate={new Date()}
                                    showTimeInput
                                    selectsEnd
                                    isClearable
                                    timeFormat="p"
                                    timeInputLabel="Time:"
                                    dateFormat="dd.MM.yyyy hh:mm aa" />
                            </Col>
                            <Form inline>
                                <Form.Check onClick={this.checkRadioInput} custom type="radio" id="r_direction_any" value="any" label="any" className="mt-1 ml-3" name="choseNwType" defaultChecked />
                                <Form.Check onClick={this.checkRadioInput} custom type="radio" id="r_direction_src" value="src" label="src" className="mt-1 ml-3" name="choseNwType" />
                                <Form.Check onClick={this.checkRadioInput} custom type="radio" id="r_direction_dst" value="dst" label="dst" className="mt-1 ml-3" name="choseNwType" />
                            </Form>
                            <InputGroup className="mb-3" size="sm">
                                <FormControl
                                    id="input_ip_network_port"
                                    aria-describedby="basic-addon2"
                                    onChange={this.handlerInput}
                                    //isValid={this.state.inputFieldIsValid}
                                    //isInvalid={this.state.inputFieldIsInvalid} 
                                    placeholder="введите ip адрес, подсеть или сетевой порт" />
                                <InputGroup.Append>
                                    <Button onClick={this.addPortNetworkIP} variant="outline-secondary">
                                    добавить
                                    </Button>
                                </InputGroup.Append>
                            </InputGroup>
                            <Button size="sm" onClick={this.addPortNetworkIP} variant="outline-primary">
                                    поиск
                            </Button>
                        </Col>
                    </Row>
                </Card>
            </React.Fragment>
        );
    }
}

CreateBodySearchTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listSources: PropTypes.object.isRequired,
    handlerChosen: PropTypes.func.isRequired,
};