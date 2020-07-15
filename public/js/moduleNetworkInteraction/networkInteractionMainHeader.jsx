import React from "react";
import ReactDOM from "react-dom";
import { Alert, Spinner } from "react-bootstrap";
import PropTypes from "prop-types";

import CreatingWidgets from "./createWidgets.jsx";
import PageManagingNetworkInteractions from "./pageManagingNetworkInteractions.jsx";

class CreatePageManagingNetworkInteractions extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "connectionModuleNI": this.connModuleNI.call(this),
            "widgets": {
                numConnect: this.props.listItems.widgetsInformation.numConnect,
                numDisconnect: this.props.listItems.widgetsInformation.numDisconnect,
                numProcessFiltration: this.props.listItems.widgetsInformation.numProcessFiltration,
                numProcessDownload: this.props.listItems.widgetsInformation.numProcessDownload,
            },
            listSources: this.props.listItems.listSources,
        };

        this.handlerEvents.call(this);
        this.requestEmiter.call(this);
    }

    connModuleNI(){
        return (typeof this.props.listItems !== "undefined") ? this.props.listItems.connectionModules.moduleNI: false;
    }

    requestEmiter(){
        this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: {} });
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "connectModuleNI"){
                if(data.options.connectionStatus){
                    this.setState({ "connectionModuleNI": true });
                } else {
                    this.setState({ "connectionModuleNI": false });
                    this.setState({"widgets": {
                        numConnect: 0,
                        numDisconnect: 0,
                    }});
                }
            }
        });

        this.props.socketIo.on("module-ni:change sources connection", (data) => {
            this.setState({"widgets": data});
        });

        //изменяем статус подключения источника для списка выбопа источника
        this.props.socketIo.on("module-ni:change status source", (data) => {
            let objCopy = Object.assign({}, this.state);
            
            console.log("received event 'module-ni:change status source'");
            console.log(data);

            for(let source in objCopy.listSources){
                if(+data.options.sourceID === +source){
                    objCopy.listSources[source].connectTime = data.options.connectTime;
                    objCopy.listSources[source].connectStatus = data.options.connectStatus;

                    this.setState(objCopy);

                    break;
                }
            }
        });
    }

    showModuleConnectionError(){
        if(!this.state.connectionModuleNI){
            return (                
                <React.Fragment>
                    <br/>
                    <Alert variant="danger">
                        <Alert.Heading>Ошибка! Модуль управления сетевыми взаимодействиями.</Alert.Heading>
                        <p>
                        Отсутствует доступ к модулю. Невозможно управление сетевыми взаимодействиями
                        с удаленными источниками.
                        </p>
                    </Alert>
                    <h6>
                        Соединение&nbsp;<Spinner animation="border" variant="primary" size="sm"/>
                    </h6>
                    
                </React.Fragment>
            );
        }
    }

    render(){
        return (
            <React.Fragment>
                <CreatingWidgets 
                    widgets={this.state.widgets} 
                    socketIo={this.props.socketIo} />
                {this.showModuleConnectionError.call(this)}
                <PageManagingNetworkInteractions
                    socketIo={this.props.socketIo}
                    listSources={this.state.listSources}
                    userPermission={this.props.listItems.userPermissions}
                    connectionModuleNI={this.props.listItems.connectionModules.moduleNI} />
            </React.Fragment>
        );
    }
}

CreatePageManagingNetworkInteractions.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageManagingNetworkInteractions
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));