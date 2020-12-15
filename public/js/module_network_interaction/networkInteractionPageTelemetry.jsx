import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import Paper from "@material-ui/core/Paper";
import PropTypes from "prop-types";

import CreateChipSource from "../commons/createChipSource.jsx";
import CreateSourceList from "../commons/createSourceList.jsx";
import CreateCardSourceTelemetry from "../commons/createCardSourceTelemetry.jsx";

class CreatePageTelemetry extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            chosedSource: 0,
            chosenSources: [],
            informationSource: {},
        };
    
        this.handlerEvents.call(this);


        this.compareNumeric = this.compareNumeric.bind(this);
        this.getShortSourceName = this.getShortSourceName.bind(this);
        this.createButtonRequest = this.createButtonRequest.bind(this);
        this.createButtonRequest = this.createButtonRequest.bind(this);
        this.handlerCloseCard = this.handlerCloseCard.bind(this);
        this.handlerChosenSource = this.handlerChosenSource.bind(this);
        this.handlerButtonRequest = this.handlerButtonRequest.bind(this);
        this.handlerChosenSourceDelete = this.handlerChosenSourceDelete.bind(this);
        this.createListSourceInformation = this.createListSourceInformation.bind(this);

        this.testRequest.call(this);
    }

    testRequest(){
        this.props.socketIo.emit("network interaction: get telemetry for list source", { arguments: {
            listSource: [ 1000, 1002 ],
        }});
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.instruction === "reject give information about state of source"){
                //                console.log("--- reject give information about state of source ---");
                //                console.log(data);

                let isChange = false;
                let objCopy = Object.assign({}, this.state);

                data.options.sl.forEach((item) => {
                    if(this.state.chosenSources.includes(item.id)){
                        isChange = true;
                        objCopy.chosenSources.splice(objCopy.chosenSources.indexOf(item.id), 1);
                        if(typeof objCopy.informationSource[item.id] !== "undefined"){
                            objCopy.informationSource[item.id] = {
                                status: true,
                                connectionStatus: false,
                                informationTelemetry: null,
                            };
                        }
                    }
                });

                if(isChange){
                    this.setState(objCopy);
                }
            }

            if(data.instruction === "give information about state of source"){
                //                console.log("--- give information about state of source ---");
                //                console.log(data);

                if(!this.state.chosenSources.includes(data.options.id)){
                    return;
                }

                let objCopy = Object.assign({}, this.state);
                objCopy.chosenSources.splice(objCopy.chosenSources.indexOf(data.options.id), 1);
                if(typeof objCopy.informationSource[data.options.id] !== "undefined"){
                    objCopy.informationSource[data.options.id] = {
                        status: true,
                        connectionStatus: true,
                        informationTelemetry: data.options.i,
                    };
                }
                
                this.setState(objCopy);
            }
        });
    }

    handlerChosenSource(e){
        let sourceID = +e.target.value;
        
        if((sourceID === null) || (typeof sourceID === "undefined") || (sourceID === 0)){
            return;
        }

        if(this.state.chosenSources.includes(sourceID)){
            return;
        }

        let objCopy = Object.assign({}, this.state);
        objCopy.chosedSource = sourceID;
        objCopy.chosenSources.push(sourceID);
        objCopy.chosenSources.sort(this.compareNumeric);
        this.setState( objCopy );
    }

    handlerChosenSourceDelete(sourceID){
        if(!this.state.chosenSources.includes(sourceID)){
            return;
        }

        let objCopy = Object.assign({}, this.state);
        objCopy.chosenSources.splice((objCopy.chosenSources.indexOf(sourceID)), 1);
        this.setState( objCopy );
    }

    handlerButtonRequest(){
        let objSources = {};
        this.state.chosenSources.forEach((sid) => {
            objSources[sid] = {
                status: false,
                connectionStatus: false,
                informationTelemetry: {},
            };
        });

        this.setState({ 
            chosedSource: 0,
            informationSource: objSources, 
        });

        this.props.socketIo.emit("network interaction: get telemetry for list source", { arguments: {
            listSource: this.state.chosenSources,
        }});
    }

    handlerCloseCard(sid){
        let objCopy = Object.assign({}, this.state);
        delete objCopy.informationSource[sid];
        this.setState( objCopy );
    }

    compareNumeric(a, b) {
        if (a > b) return 1;
        if (a == b) return 0;
        if (a < b) return -1;
    }

    createButtonRequest(){
        if(this.state.chosenSources.length === 0){
            return null;
        }

        return (
            <Button 
                size="sm"
                variant="outline-primary" 
                onClick={this.handlerButtonRequest}>
                отправить запрос
            </Button>
        );
    }

    createCommonTelemetryInformation(){
        if(Object.keys(this.state.informationSource).length !== 0){
            return null;
        }

        return (
            <Row>
                <Col>
                    <Paper>Здесь будет общая информация о телеметри источников</Paper>
                </Col>
            </Row> 
        );
    }

    createListSourceInformation(){
        let list = [];

        for(let sid in this.state.informationSource){
            list.push(<Row className="pt-2" key={`key_card_${sid}`}><Col>
                <CreateCardSourceTelemetry 
                    sourceID={sid}
                    sourceInfo={this.state.informationSource[sid]} 
                    sourceShortName={this.getShortSourceName(sid)}
                    handleClose={this.handlerCloseCard} />
            </Col></Row>);
        }

        return <React.Fragment>{list}</React.Fragment>;
    }

    getShortSourceName(sid){       
        let shortName = "";

        if(typeof this.props.listItems.listSources[sid] !== "undefined"){
            shortName = this.props.listItems.listSources[sid].shortName;
        }
        
        return shortName;
    }

    render(){
        return (
            <Row className="pt-3">
                <Col md={3}>
                    <Row>
                        <Col md={12}>
                            <CreateSourceList 
                                typeModal={"новая"}
                                hiddenFields={false}
                                listSources={this.props.listItems.listSources}
                                currentSource={this.state.chosedSource}
                                handlerChosen={this.handlerChosenSource}
                                swithCheckConnectionStatus={false} />
                        </Col>
                    </Row>
                    <Row>
                        <Col md={12} className="text-left">
                            <CreateChipSource 
                                chipData={this.state.chosenSources} 
                                handleDelete={this.handlerChosenSourceDelete}/>
                        </Col>
                    </Row>
                    <Row className="pt-2 text-right">
                        <Col md={12}>
                            {this.createButtonRequest()}
                        </Col>
                    </Row>
                </Col>
                <Col md={9}>
                    {this.createCommonTelemetryInformation()}                   
                    {this.createListSourceInformation()}
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