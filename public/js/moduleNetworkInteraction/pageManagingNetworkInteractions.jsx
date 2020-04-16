import React from "react";
import { Alert, Card, Spinner, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyDynamics from "./createBodyDynamics.jsx";
import CreateBodySearchTask from "./createBodySearchTask.jsx";
import CreateBodyFormationTask from "./createBodyFormationTask.jsx";

class CreatingWidgets extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <div className="row">
                <div className="col-md-2">
                    <Card border="success" style={{ width: "10rem" }}>
                        <Card.Body>
                            <small>источников</small>
                            <Card.Text>0</Card.Text>
                            <small className="text-muted">подключено</small>
                        </Card.Body>
                    </Card>
                </div>
                <div className="col-md-2">
                    <Card border="danger" style={{ width: "10rem" }}>
                        <Card.Body>
                            <small>источников</small>
                            <Card.Text>0</Card.Text>
                            <Card.Text>
                                <small className="text-muted">не доступно</small>
                            </Card.Text>
                        </Card.Body>
                    </Card>
                </div>
                <div className="col-md-2">
                    <Card border="dark" style={{ width: "10rem" }}>
                        <Card.Body>
                            <small>фильтрация</small>
                            <Card.Text>0</Card.Text>
                            <Card.Text>
                                <small className="text-muted">выполняется</small>
                            </Card.Text>
                        </Card.Body>
                    </Card>
                </div>
                <div className="col-md-3">
                    <Card border="info" style={{ width: "13rem" }}>
                        <Card.Body>
                            <small>загрузка файлов</small>
                            <Card.Text>0 / 0</Card.Text>
                            <small className="text-muted"> выполняется / доступна</small>
                        </Card.Body>
                    </Card>
                </div>
                <div className="col-md-3">
                    <Card border="info" style={{ width: "13rem" }}>
                        <Card.Body>
                            <small>загруженные файлы</small>
                            <Card.Text>0</Card.Text>
                            <small className="text-muted">нерассмотренны</small>
                        </Card.Body>
                    </Card>
                </div>
            </div>
        );
    }
}

CreatingWidgets.propTypes = {

};

export default class PageManagingNetworkInteractions extends React.Component {
    constructor(props){
        super(props);

        this.state = {};

        this.handlerEvents.call(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            /*            if(data.type === "connectModuleNI"){
                if(data.options.connectionStatus){
                    this.setState({ "connectionModuleNI": true });
                } else {
                    this.setState({ "connectionModuleNI": false });
                }
            }*/
        });
    }

    render(){
        return (
            <React.Fragment>
                <CreatingWidgets/>
                <br/>
                <Tabs defaultActiveKey="dynamics" id="uncontrolled-tab-example">
                    <Tab eventKey="dynamics" title="динамика">
                        <CreateBodyDynamics />
                    </Tab>
                    <Tab eventKey="formation_task" title="формирование задач">
                        <CreateBodyFormationTask />
                    </Tab>
                    <Tab eventKey="search_task" title="поиск">
                        <CreateBodySearchTask />
                    </Tab>
                    <Tab eventKey="statistics_and_analytics" title="статистика и аналитика">
                        {"страница статистики и аналитики"}
                    </Tab>
                    <Tab eventKey="sources_telemetry" title="телеметрия с источников">
                        {"страница телеметрии источников"}
                    </Tab>
                </Tabs>
            </React.Fragment>
        );
    }
}

PageManagingNetworkInteractions.propTypes = {
    socketIo: PropTypes.object.isRequired,
};