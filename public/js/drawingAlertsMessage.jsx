"use strict";

import React from "react";
import PropTypes from "prop-types";
import { Snackbar } from "material-ui-core";
import { Alert } from "material-ui-lab";

class DrawingAlertMessage extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showSnackbar: true
        };

        this.titleObj = {
            "success": {
                title: "Успешно выполненное действие.",
                severity: "success",
            },
            "info": {
                title: "Информация.",
                severity: "info",
            },
            "warning": {
                title: "Внимание!",
                severity: "warning",
            },
            "error": {
                title: "Ошибка!!!",
                severity: "error",
            },
        };
    }

    handleClose(){
        this.setState({ showSnackbar: false });
    }

    render(){
        let level = (this.props.notiyMsg.type === "danger")? "error": this.props.notiyMsg.type;

        if(typeof this.titleObj[level] === "undefined"){
            return null;
        }

        return (
            <Snackbar 
                open={this.state.showSnackbar} 
                onClose={this.handleClose.bind(this)} 
                autoHideDuration={6000} 
                anchorOrigin={{ vertical: "top", horizontal: "right" }}>
                <Alert onClose={this.handleClose.bind(this)} severity={this.titleObj[level].severity}>
                    {this.props.notiyMsg.message}
                </Alert>
            </Snackbar>
        );
    }
}

DrawingAlertMessage.propTypes = {
    socketIo: PropTypes.object.isRequired,
    notiyMsg: PropTypes.object.isRequired,
};

export { DrawingAlertMessage };
