import React from "react";
import { Col, Row, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodySearchTask extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
                <Row>
                    <Col md={12}>
                    здесь будут параметры поиска информации
                    </Col>
                </Row>
            </React.Fragment>
        );
    }
}

CreateBodySearchTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
};