import React from "react";
import { Card, Col, Row, Button, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreateBodySearchTask extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
                <Card className="mb-2" body>
                    <Row>
                        <Col md={12}>
                    здесь будут параметры поиска информации
                        </Col>
                    </Row>
                </Card>
            </React.Fragment>
        );
    }
}

CreateBodySearchTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
};