/**
 * Модуль формирующий информационные сообщения на странице
 * 
 * Версия 0.1, дата релиза 12.12.2019
 */

"use strict";

import React from "react";
import ReactDOM from "react-dom";

import { Alert } from "react-bootstrap";
import PropTypes from "prop-types";

class CreateAlert extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            alertShow: false,
            type: "",
            message: "",
        };

        this.handlerClose = this.handlerClose.bind(this);
        
        this.eventsListener();
    }

    eventsListener(){
        this.props.socketIo.on("notify information", msg => {
            console.log(msg);

            let msgObj = JSON.parse(msg.notify);

            this.setState({
                alertShow: true,
                type: msgObj.type,
                message: msgObj.message,
            });
        });
    }

    handlerClose(){
        this.setState({
            alertShow: false,
            type: "",
            message: "",
        });
    }

    render(){
        if(!this.state.alertShow){
            return <div></div>;
        }

        return (
            <Alert variant={this.state.type} onClose={this.handlerClose} dismissible>
                {this.state.message}
            </Alert>);
    }
}

CreateAlert.propTypes = {
    socketIo: PropTypes.object.isRequired,
};

ReactDOM.render(<CreateAlert socketIo={socket} />, document.getElementById("location-alerts"));