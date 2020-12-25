import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateSteppersTemplateLog from "../commons/createSteppersTemplateLog.jsx";

class CreatePageTemplateLog extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            steppers: ["one" , "two", "tree"],
        };
    }

    createForm(){
        return "form";
    }

    render(){
        return (
            <React.Fragment>
                <Row>
                    <Col md={12}>
                        <CreateSteppersTemplateLog steppers={this.state.steppers}/>
                    </Col>
                </Row>
                <Row>
                    <Col md={12}>{this.createForm.call(this)}</Col>
                </Row>
                <Row>
                    <Col md={12}>
                        здесь будет список задач
                        с кратким описанием, при этом
                        будет тип задачи (телеметрия, фильтрация)
                    </Col>
                </Row>
            </React.Fragment>
        );
    }
}

CreatePageTemplateLog.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageTemplateLog
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));