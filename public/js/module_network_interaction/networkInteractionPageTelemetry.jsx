import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Form, Row, Table, Tooltip, OverlayTrigger } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateChipSource from "../commons/createChipSource.jsx";
import CreateSourceList from "../commons/createSourceList.jsx";

class CreatePageTelemetry extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            chosenSources: [],
            informationSource: {},
        };
        //        this.getListSource = this.getListSource.bind(this);
    
        console.log(this.props.listItems);

        this.handlerEvents.call(this);
        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handlerChosenSourceDelete = this.handlerChosenSourceDelete.bind(this);

        this.testRequest.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.instruction === "reject give information about state of source"){
                console.log("--- reject give information about state of source ---");
                console.log(data);
            }

            if(data.instruction === "give information about state of source"){
                console.log("--- give information about state of source ---");
                console.log(data);
            }
        });
    }

    handlerChosenSource(e){
        let sourceID = +e.target.value;
        if((sourceID === null) || (typeof sourceID === "undefined")){
            return;
        }

        console.log("func 'handlerChosenSource', START...");
        console.log(`chosen source id: '${sourceID}'`);

        if(this.state.chosenSources.includes(sourceID)){
            return;
        }

        let objCopy = Object.assign({}, this.state);
        objCopy.chosenSources.push(sourceID);
        objCopy.chosenSources.sort();
        this.setState( objCopy );
    }

    handlerChosenSourceDelete(e){
        console.log("func 'handlerChosenSourceDelete', Start...");
        console.log(e);
    }

    testRequest(){
        this.props.socketIo.emit("network interaction: get telemetry for list source", { arguments: {
            listSource: [ 1000, 1002 ],
        }});
    }
    /*    getListSource(){
        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID, num) => {
            return (
                <option 
                    key={`key_source_${num}_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }*/

    render(){
        return (
            <Row className="pt-3">
                <Col md={3}>
                    <Row>
                        <Col>
                            <CreateSourceList 
                                typeModal={"новая"}
                                hiddenFields={false}
                                listSources={this.props.listItems.listSources}
                                currentSource={0}
                                handlerChosen={this.handlerChosenSource} />
                        </Col>
                    </Row>
                    <Row>
                        <Col>
                            <CreateChipSource 
                                chipData={this.state.chosenSources} 
                                handleDelete={this.handlerChosenSourceDelete}/>
                        </Col>
                    </Row>
                </Col>
                <Col md={9}>
        Телеметрия, тестовая страница
                </Col>
            </Row>
        );
    }
}

CreatePageTelemetry.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageTelemetry
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));