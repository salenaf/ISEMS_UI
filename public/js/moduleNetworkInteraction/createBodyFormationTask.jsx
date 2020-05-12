import React from "react";
import { Badge, Button, Card, Col, Spinner, Form, FormControl, InputGroup, Tab, Tabs, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyDynamics from "./createBodyDynamics.jsx";
import ModalWindowAddFilteringTask from "../modalwindows/modalWindowAddFilteringTask.jsx";
import ModalWindowListTaskDownloadFiles from "../modalwindows/modalWindowListTaskDownloadFiles.jsx";

export default class CreateBodyFormationTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showModalWindowFiltration: false,
            showModalWindowListDownload: false,
        };

        this.handlerButtonSubmitWindowFilter = this.handlerButtonSubmitWindowFilter.bind(this);
        this.handlerButtonSubmitWindowDownload = this.handlerButtonSubmitWindowDownload.bind(this);
        this.handlerShowModalWindowFiltration = this.handlerShowModalWindowFiltration.bind(this);
        this.handlerCloseModalWindowFiltration = this.handlerCloseModalWindowFiltration.bind(this);
        this.handlerShowModalWindowListDownload = this.handlerShowModalWindowListDownload.bind(this);
        this.handlerCloseModalWindowListDownload = this.handlerCloseModalWindowListDownload.bind(this);

        //        console.log(this.props.listSources);
    }

    handlerButtonSubmitWindowFilter(objTaskInfo){
        console.log("func 'handlerButtonSubmit', START...");
        console.log(objTaskInfo);
    }

    handlerButtonSubmitWindowDownload(){
        console.log("func 'handlerButtonSubmitWindowDownload', START...");
    }


    handlerShowModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: true });
    }

    handlerCloseModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: false });
    }

    handlerShowModalWindowListDownload(){
        this.setState({ showModalWindowListDownload: true });
    }

    handlerCloseModalWindowListDownload(){
        this.setState({ showModalWindowListDownload: false });
    }

    render(){
        return (
            <React.Fragment>
                <Row className="mt-3 mb-3">
                    <Col sm="8"></Col>
                    <Col className="text-right">
                        <Button variant="outline-primary" onClick={this.handlerShowModalWindowFiltration} size="sm">
                            фильтрация
                        </Button>
                        <Button variant="outline-primary" onClick={this.handlerShowModalWindowListDownload} size="sm" className="ml-1">
                            загрузка <Badge variant="light">0</Badge>
                            <span className="sr-only">unread messages</span>
                        </Button>
                    </Col>
                </Row>
                <CreateBodyDynamics />
                <ModalWindowAddFilteringTask 
                    show={this.state.showModalWindowFiltration}
                    onHide={this.handlerCloseModalWindowFiltration}
                    listSources={this.props.listSources}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowFilter} />
                <ModalWindowListTaskDownloadFiles 
                    show={this.state.showModalWindowListDownload}
                    onHide={this.handlerCloseModalWindowListDownload}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowDownload} />
            </React.Fragment>
        );
    }
}

CreateBodyFormationTask.propTypes = {
    listSources: PropTypes.object.isRequired
};