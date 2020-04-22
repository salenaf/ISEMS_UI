import React from "react";
import { Alert, Card, Spinner, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodySearchTask extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
                {"Поиск задач"}
            </React.Fragment>
        );
    }
}

CreateBodySearchTask.propTypes = {

};