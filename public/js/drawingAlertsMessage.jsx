"use strict";

import React from "react";
import PropTypes from "prop-types";
import { MDBContainer, MDBNotification } from "mdbreact";

class DrawingAlertMessage extends React.Component {
    constructor(props){
        super(props);

        this.titleObj = {
            "success": {
                title: "Успешно выполненное действие.",
                icon: "envelope",
                iconColor: "text-success",
            },
            "info": {
                title: "Информация.",
                icon: "info-circle",
                iconColor: "text-info",
            },
            "warning": {
                title: "Внимание!",
                icon: "exclamation-triangle",
                iconColor: "text-warning",
            },
            "error": {
                title: "Ошибка!!!",
                icon: "exclamation-circle",
                iconColor: "text-danger",
            },
        };
    }

    render(){
        let level = (this.props.notiyMsg.type === "danger")? "error": this.props.notiyMsg.type;

        if(typeof this.titleObj[level] === "undefined"){
            return null;
        }

        return (
            <MDBContainer
                style={{
                    width: "auto",
                    position: "fixed",
                    top: "10px",
                    right: "10px",
                    zIndex: 9999
                }}
            >
                <MDBNotification
                    show
                    fade
                    autohide={6000}
                    icon={this.titleObj[level].icon}
                    iconClassName={this.titleObj[level].iconColor}
                    title={this.titleObj[level].title}
                    message={this.props.notiyMsg.message}
                />
            </MDBContainer>
        );
    }
}

DrawingAlertMessage.propTypes = {
    socketIo: PropTypes.object.isRequired,
    notiyMsg: PropTypes.object.isRequired,
};

export { DrawingAlertMessage };
