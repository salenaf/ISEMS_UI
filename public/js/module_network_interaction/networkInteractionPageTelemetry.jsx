import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateChipSource from "../commons/createChipSource.jsx";
import CreateSourceList from "../commons/createSourceList.jsx";
import CreateCardSourceTelemetry from "../commons/createCardSourceTelemetry.jsx";
import CreateCardSourceTelemetryProblemParameters from "../commons/createCardSourceTelemetryProblemParameters.jsx";

class CreatePageTelemetry extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            chosedSource: 0,
            chosenSources: [],
            informationSource: {},
            telemetryDeviationParameters: this.props.listItems.mainInformation.listSourceDeviationParameters,
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
        this.handleDeleteCardProblemParameters = this.handleDeleteCardProblemParameters.bind(this);
        this.createListSourceInformation = this.createListSourceInformation.bind(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.instruction === "reject give information about state of source"){
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

                            if((typeof item.timeReceipt !== "undefined") && (typeof item.telemetryParameters !== "undefined")){
                                objCopy.informationSource[item.id].timeReceipt = item.timeReceipt;
                                objCopy.informationSource[item.id].informationTelemetry = item.telemetryParameters;
                            }
                        }
                    }
                });

                if(isChange){
                    this.setState(objCopy);
                }
            }

            if(data.instruction === "give information about state of source"){              
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

            if(data.type === "telemetryDeviationParameters"){
                this.setState({ telemetryDeviationParameters: data.options });
            }

            if(data.type === "deletedTelemetryDeviationParameters"){
                let sourceID = +data.options.sourceID;
                if(isNaN(sourceID)){
                    return;
                }

                let tmpList = this.state.telemetryDeviationParameters;
                for(let num = 0; num < tmpList.length; num++){
                    if(+tmpList[num].sourceID === sourceID){
                        tmpList.splice(num, 1);    

                        break;
                    }
                }

                this.setState({ telemetryDeviationParameters: tmpList });
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

    handleDeleteCardProblemParameters(sourceID){
        this.props.socketIo.emit("network interaction: delete information problem patameters", { arguments: {
            sourceID: sourceID,
        }});
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

        if(this.state.telemetryDeviationParameters.length === 0){
            return null;
        }

        return (
            <React.Fragment>
                {this.state.telemetryDeviationParameters.map((item) => {
                    return (
                        <Row className="pt-2" key={`key_card_${item.sourceID}`}>
                            <Col>
                                <CreateCardSourceTelemetryProblemParameters 
                                    sourceInfo={item}
                                    handleDeleteCard={this.handleDeleteCardProblemParameters} />
                            </Col>
                        </Row>
                    );
                })}
            </React.Fragment>
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
            <React.Fragment>
                <Row className="pt-3">
                    <Col md={5} className="text-left">
                        <CreateSourceList 
                            typeModal={"новая"}
                            hiddenFields={false}
                            listSources={this.props.listItems.listSources}
                            currentSource={this.state.chosedSource}
                            handlerChosen={this.handlerChosenSource}
                            swithCheckConnectionStatus={false} />        
                    </Col>
                    <Col md={5} className="mt-n1 text-left">
                        <CreateChipSource 
                            chipData={this.state.chosenSources} 
                            handleDelete={this.handlerChosenSourceDelete}/>
                    </Col>
                    <Col md={2} className="text-right">
                        {this.createButtonRequest()}
                    </Col>
                </Row>
                <Row className="pt-2">
                    <Col md={12}>
                        {this.createCommonTelemetryInformation()}                   
                        {this.createListSourceInformation()}
                    </Col>
                </Row>
            </React.Fragment>
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