/**
 * Модуль формирования модального окна для изменения дефолтного
 * пароля администратора
 * 
 * Версия 0.1, дата релиза 17.12.2019
 */

"use strict";

import React from "react";
import { Button, Modal, Form } from "react-bootstrap";
import PropTypes from "prop-types";

export { ModalWindowChangeAdminPasswd };

class ModalWindowChangeAdminPasswd extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return <div></div>;
    }
}

ModalWindowChangeAdminPasswd.propTypes = {
    login: PropTypes.string.isRequired,
    passIsDefault: PropTypes.bool,
};