import React from "react";
import ReactDOM from "react-dom";
import { Alert, Card, Spinner, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

import CreatingWidgets from "./createWidgets.jsx";
import PageManagingNetworkInteractions from "./pageManagingNetworkInteractions.jsx";

class CreatePageManagingNetworkInteractions extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            "connectionModuleNI": this.connModuleNI.call(this),
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
                <CreatingWidgets  />
                {this.showModuleConnectionError.call(this)}
                <PageManagingNetworkInteractions socketIo={this.props.socketIo} />
            </React.Fragment>
        );
    }
}

CreatePageManagingNetworkInteractions.propTypes = {
    socketIo: PropTypes.object.isRequired,
    mainInfo: PropTypes.object.isRequired,
    userAccess: PropTypes.object.isRequired,
    widgetInfo: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageManagingNetworkInteractions
    socketIo={socket}
    mainInfo={receivedFromServerMain}
    userAccess={receivedFromServerAccess}
    widgetInfo={receivedFromServerWidget} />, document.getElementById("main-page-content"));