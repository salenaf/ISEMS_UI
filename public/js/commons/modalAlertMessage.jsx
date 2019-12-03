/**
 * Модуль формирования сообщения об ошибке при выполнении валидации в модальном окне
 * 
 * Версия 0.1, дата релиза 03.12.2019
 */

"use strict";

import React from "react";
import { Alert } from "react-bootstrap";
import PropTypes from "prop-types";

export { ModalAlertDangerMessage };

class ModalAlertDangerMessage extends React.Component {
    render() {
        return (<>
            <Alert dismissible variant="danger" show={this.props.show} onClose={this.props.onClose}>
                <Alert.Heading className={"text-center"}>{this.props.children}</Alert.Heading>
                <p>{this.props.message}</p>
            </Alert>
        </>);
    }
}

ModalAlertDangerMessage.propTypes = {
    children: PropTypes.string,
    message: PropTypes.string,
    show: PropTypes.bool.isRequired,
    onClose: PropTypes.func.isRequired,
};
