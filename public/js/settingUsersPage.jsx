/**
 * Модуль формирующий основную таблицу на странице
 * 
 * Версия 0.1, дата релиза 28.11.2019
 */

"use strict";

import React from "react";
import ReactDOM from "react-dom";

import { Alert, Button, Table } from "react-bootstrap";
import PropTypes from "prop-types";

import { helpers } from "./common_helpers/helpers";
import showNotifyMessage from "./common_helpers/showNotifyMessage";


class CreateTable extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return;
    }
}

CreateTable.propTypes = {
    mainInformation: PropTypes.object.isRequired,
    accessRights: PropTypes.object.isRequired
};

ReactDOM.render(<CreateTable 
    mainInformation={receivedFromServerMain} 
    accessRights={receivedFromServerAccess} />, document.getElementById("field_information"));