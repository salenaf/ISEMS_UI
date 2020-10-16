import React from "react";
import ReactDOM from "react-dom";
import { Col, Row, Table, Pagination } from "react-bootstrap";
import PropTypes from "prop-types";

class CreatePageStatisticsAndAnalyticsDetalTask extends React.Component {
    constructor(props){
        super(props);
    }

    render(){
        return <div>Подробно о задаче</div>;
    }
}
/**
 * здесь нужно добавить эконку <- и привязать к нее событие window back
 * или как то так оно называется
 */
CreatePageStatisticsAndAnalyticsDetalTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreatePageStatisticsAndAnalyticsDetalTask
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));
