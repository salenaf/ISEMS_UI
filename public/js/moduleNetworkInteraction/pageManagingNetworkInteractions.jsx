import React from "react";
import { Alert, Card, Spinner, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodySearchTask from "./createBodySearchTask.jsx";
import CreateBodyFormationTask from "./createBodyFormationTask.jsx";

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
                <br/>
                <Tabs defaultActiveKey="formation_task" id="uncontrolled-tab-example">
                    <Tab eventKey="formation_task" title="задачи">
                        <CreateBodyFormationTask 
                            listSources={this.props.listSources} />
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
    listSources: PropTypes.object.isRequired,
};