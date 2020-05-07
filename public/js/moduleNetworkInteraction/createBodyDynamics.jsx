import React from "react";
import { Col, Card, ProgressBar, Row, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodyDynamics extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
                <Card className="mb-3">
                    {"1023 - Sensor MER (задача: скачивание файлов)"}
                    <div className="pl-2 pr-2">
                        <ProgressBar now="65" label={"65%"}/>
                    </div>
                    <small className="text-muted">
                        {"файлов загруженных / всего: 3 / 12"}
                    </small>
                </Card>
                <Card className="mb-3">
                    {"1052 - AO Vladimir (задача: фильтрация файлов)"}
                    <div className="pl-2 pr-2">
                        <ProgressBar now="78" label={"132/245"}/>
                    </div>
                    <small className="text-muted">
                        {"файлов найдено / обработано / всего: 13 / 132 / 245"}
                    </small>
                </Card>
            </React.Fragment>
        );
    }
}

CreateBodyDynamics.propTypes = {

};