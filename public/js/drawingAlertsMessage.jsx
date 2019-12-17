/**
 * Модуль формирующий информационные сообщения на странице
 * 
 * Версия 1.0, дата релиза 16.12.2019
 */

"use strict";

import React from "react";
import ReactDOM from "react-dom";
import { AlertList } from "react-bs-notifier";

import PropTypes from "prop-types";

class CreateAlert extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            alertShow: false,
        };

        this.alerts = [];
        this.handlerClose = this.handlerClose.bind(this);
        
        this.eventsListener();
    }

    eventsListener(){
        this.props.socketIo.on("notify information", data => {
            let msg = JSON.parse(data.notify);

            this.alerts.push({
                id: msg.id,
                type: msg.type,
                message: `${msg.message}  .`,
            });

            this.setState({
                alertShow: true,
            });
        });
    }

    handlerClose(elem){
        let newAlert = [];
        this.alerts.forEach(item => {
            if(item.id !== elem.id){
                newAlert.push(item);
            } 
        });
        this.alerts = newAlert;

        this.setState({
            alertShow: false,
        });
    }

    render(){
        return <AlertList alerts={this.alerts} dismissTitle={"закрыть"} onDismiss={this.handlerClose} timeout={5000}/>;
    }
}

CreateAlert.propTypes = {
    socketIo: PropTypes.object.isRequired,
};

ReactDOM.render(<CreateAlert socketIo={socket} />, document.getElementById("location-alerts"));