import React from "react";
import { Alert, Button, Card, Col, Spinner, Form, FormControl, InputGroup, Tab, Tabs, Row } from "react-bootstrap";
import PropTypes from "prop-types";

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

export default class CreateBodyFormationTask extends React.Component {
    constructor(props){
        super(props);

        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handlerChosenProtocol = this.handlerChosenProtocol.bind(this);

        //        console.log(this.props.listSources);
    }

    handlerChosenSource(e){
        console.log("func 'handlerChosenSource'");
        console.log(e.target.value);
    }

    handlerChosenProtocol(e){
        console.log("func 'handlerChosenProtocol'");
        console.log(e.target.value);
    }

    render(){
        return (
            <React.Fragment>
                <br/>
                <Card border="info" body>
                    <Form>
                        <Form.Group as={Row} controlId="formListSources">
                            <Col sm="2">источник</Col>
                            <Col sm="4" className="text-left">
                                <CreateSourceList 
                                    listSources={this.props.listSources}
                                    handlerChosen={this.handlerChosenSource} />
                            </Col>
                            <Col sm="2">протокол</Col>
                            <Col sm="2" className="text-left">
                                <CreateProtocolList handlerChosen={this.handlerChosenProtocol} />
                            </Col>
                            <Col sm="2"></Col>                            
                        </Form.Group>
                        <Form.Group as={Row} controlId="formListSources">
                            <Col sm="2"></Col>
                            <Col sm="10" className="text-left">
                            </Col>                            
                        </Form.Group>
                    </Form>
                </Card>
            </React.Fragment>
        );
    }
}

CreateBodyFormationTask.propTypes = {
    listSources: PropTypes.object.isRequired
};