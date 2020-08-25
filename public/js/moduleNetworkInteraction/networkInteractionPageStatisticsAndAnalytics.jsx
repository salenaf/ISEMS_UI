import React from "react";
import ReactDOM from "react-dom";
import { Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

export default class CreatePageStatisticsAndAnalytics extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left text-muted">статистика и аналитика</Col>
                </Row>
                <Row>
                    <Col md={12}></Col>
                </Row>
            </React.Fragment>
        );
    }
}

CreatePageStatisticsAndAnalytics.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreatePageStatisticsAndAnalytics
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));
