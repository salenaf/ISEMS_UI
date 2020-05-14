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
            },
            listSources: this.props.listItems.listSources,
        };

        this.handlerEvents.call(this);
    }

    connModuleNI(){
        return (typeof this.props.listItems !== "undefined") ? this.props.listItems.connectionModules.moduleNI: false;
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
                <CreatingWidgets widgets={this.state.widgets} />
                {this.showModuleConnectionError.call(this)}
                <PageManagingNetworkInteractions
                    socketIo={this.props.socketIo}
                    listSources={this.state.listSources}
                    userPermission={this.props.listItems.userPermissions} />
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