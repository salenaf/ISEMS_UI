import React from "react";
import { Badge, Button, Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodyDownloadFiles extends React.Component {
    constructor(props){
        super(props);

        this.state = {
        };
    }

    render(){
        return (
            <Row>
                <Col>страница загрузки файлов</Col>
            </Row>);
    }
}

CreateBodyDownloadFiles.propTypes = {
    socketIo: PropTypes.object.isRequired,
};