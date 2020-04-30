import React from "react";
import { Card } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreatingWidgets extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <div className="row d-flex justify-content-center">
                <Card className="ml-3" border="success" style={{ width: "10rem" }}>
                    <small>источников</small>
                    <span className="mb-0 text-success">{this.props.widgets.numConnect}</span>
                    <small className="text-muted">подключено</small>
                </Card>
                <Card className="ml-3" border="danger" style={{ width: "10rem" }}>
                    <small>источников</small>
                    <span className="mb-0 text-danger">{this.props.widgets.numDisconnect}</span>
                    <small className="text-muted">не доступно</small>
                </Card>
                <Card className="ml-3" border="dark" style={{ width: "10rem" }}>
                    <small>фильтрация</small>
                    <span className="mb-0">0</span>
                    <small className="text-muted">выполняется</small>
                </Card>
                <Card className="ml-3" border="info" style={{ width: "13rem" }}>
                    <small>загрузка файлов</small>
                    <span className="mb-0">0 / 0</span>
                    <small className="text-muted"> выполняется / доступна</small>
                </Card>
                <Card className="ml-3" border="info" style={{ width: "13rem" }}>
                    <small>загруженные файлы</small>
                    <span className="mb-0">0</span>
                    <small className="text-muted">нерассмотренны</small>
                </Card>
            </div>
        );
    }
}

CreatingWidgets.propTypes = {
    widgets: PropTypes.object.isRequired,
};