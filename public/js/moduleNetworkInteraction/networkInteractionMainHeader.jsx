import React from "react";
import ReactDOM from "react-dom";
import { Alert, Card, Spinner, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

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
            return (                <React.Fragment>
                <Alert variant="danger">
                    <Alert.Heading>Модуль управления сетевыми взаимодействиями.</Alert.Heading>
                    <p>
                        Отсутствует доступ к модулю. Управление сетевыми взаимодействиями
                        с удаленными источниками невозможно.
                    </p>
                </Alert>
                <h6>Соединение...</h6>
                <Spinner animation="border" variant="danger"/>
            </React.Fragment>
            );
        }
    }

    render(){
        return (
            <React.Fragment>
                {this.showModuleConnectionError.call(this)}
                <PageManagingNetworkInteractions socketIo={this.props.socketIo} />
            </React.Fragment>
        );
    }
}

CreatePageManagingNetworkInteractions.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
/*    listShortEntity: PropTypes.object.isRequired,
    userPermissions: PropTypes.object.isRequired,
    listFieldActivity: PropTypes.array.isRequired,*/
}; 

ReactDOM.render(<CreatePageManagingNetworkInteractions
    socketIo={socket} 
    listItems={resivedFromServer} />, document.getElementById("main-page-content"));