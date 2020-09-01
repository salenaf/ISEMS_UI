import React from "react";
import { Button, Card, Col, Form, Row, FormControl, InputGroup } from "react-bootstrap";
import PropTypes from "prop-types";

import DatePicker from "react-datepicker";
import TokenInput from "react-customize-token-input";

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

        this.state = {
            sourceID: 0,
            statusFiltering: "",
            statusDownload: "",
        };

        this.getListSource = this.getListSource.bind(this);
        
        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handlerChosenProtocolList = this.handlerChosenProtocolList.bind(this);
        this.handlerChosenStatusDownload = this.handlerChosenStatusDownload.bind(this);
        this.handlerChosenStatusFiltering = this.handlerChosenStatusFiltering.bind(this);
    }

    handlerChosenSource(e){
        console.log("func 'handlerChosenSource', START...");
        console.log(`был выбран источник с ID '${+(e.target.value)}'`);
    }

    handlerChosenStatusFiltering(e){
        console.log("func 'handlerChosenStatusFiltering', START...");
        console.log(`был выбран статус фильтрации '${e.target.value}'`);
    }

    handlerChosenStatusDownload(e){
        console.log("func 'handlerChosenStatusDownload', START...");
        console.log(`был выбран статус скачивания '${e.target.value}'`);
    }

    handlerChosenProtocolList(e){
        console.log("func 'handlerChosenProtocolList', START...");
        console.log(`был выбран сетевой протокол '${e.target.value}'`);
    }

    onTagsChanged(tags) {
        this.setState({tags});
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
                            <Form.Control onChange={this.handlerChosenSource} as="select" size="sm">
                                <option value={0}>источник</option>
                                {this.getListSource()}
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenStatusFiltering} as="select" size="sm">
                                <option value="">статус фильтрации</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col}>
                            <Form.Control onChange={this.handlerChosenStatusDownload} as="select" size="sm">
                                <option value="">статус выгрузки файлов</option>
                                <option value="wait">готовится к выполнению</option>
                                <option value="refused">oтклонена</option>
                                <option value="execute">выполняется</option>
                                <option value="not executed">не выполнялась</option>
                                <option value="complete">завершена успешно</option>
                                <option value="stop">остановлена пользователем</option>
                            </Form.Control>
                        </Form.Group>
                        <Form.Group as={Col} className="mt-1 ml-3">
                            <Form.Row>
                                <Form.Check type="checkbox"/>
                                <small className="ml-1">задача</small>
                                <Form.Check  custom type="radio" value={true} label="" className="mt-1 ml-3" name="choseTaskComplete" defaultChecked />
                                <small className="ml-1">закрыта</small>
                                <Form.Check  custom type="radio" value={false} label="" className="mt-1 ml-3" name="choseTaskComplete" />
                                <small className="ml-1">открыта</small>
                            </Form.Row>
                        </Form.Group>
                    </Form.Row>
                    {/**
                    Нужно сделать активирование checkbox для
                    - файлы найдены 
                    - выгрузка выполнялась
                    - все файлы выгружены
                     */}
                    <Form.Row>
                        <Form.Group as={Col} className="text-left">
                            <Form.Row className="ml-1 mb-n1">
                                <Form.Check type="checkbox"/>
                                <small className="ml-1">файлы найдены</small>
                            </Form.Row>
                            <Form.Row className="ml-1 mb-n1">
                                <Form.Check type="checkbox"/>
                                <small className="ml-1">выгрузка выполнялась</small>
                            </Form.Row>
                            <Form.Row className="ml-1">
                                <Form.Check type="checkbox"/>
                                <small className="ml-1">все файлы выгружены</small>
                            </Form.Row>
                        </Form.Group>
                        <Form.Group as={Col} className="text-left">
                            <small>кол-во файлов</small>
                            <Form.Row>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="min" />
                                </Form.Group>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="max" />
                                </Form.Group>
                            </Form.Row>
                        </Form.Group>
                        <Form.Group as={Col} className="text-left">
                            <small>размер файлов</small>
                            <Form.Row>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="min" />
                                </Form.Group>
                                <Form.Group as={Col}>
                                    <Form.Control type="input" size="sm" placeholder="max" />
                                </Form.Group>
                            </Form.Row>
                        </Form.Group>    
                    </Form.Row>                    
                    <Form.Row className="mt-n3">
                        <Col md={5}>
                            <Row>
                                <Col md={6}>
                                    <small className="mr-1">начальное время</small>
                                    <Form.Row>
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
                                    </Form.Row>
                                </Col>
                                <Col md={6}>
                                    <small className="mr-1">конечное время</small>
                                    <Form.Row>
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
                                    </Form.Row>
                                </Col>
                            </Row>
                        </Col>
                        <Col md={2} className="text-right">
                            <small className="mr-1">сет. протокол</small>
                            <CreateProtocolList handlerChosen={this.handlerChosenProtocolList} />
                        </Col>
                        <Col md={5}>
                            <TokenInput 
                                className="react-token-input"
                                placeholder="ip адрес, порт или подсеть" />
                        </Col>
                    </Form.Row>
                    <Row>
                        <Col className="text-right mt-2">
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
};