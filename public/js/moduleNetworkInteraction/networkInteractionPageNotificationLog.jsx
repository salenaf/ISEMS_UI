import React from "react";
import ReactDOM from "react-dom";
import { Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

class CreatePageNotificationLog extends React.Component {
    constructor(props){
        super(props);

        this.createTable = this.createTable.bind(this);

        console.log("func 'CreatePageNotificationLog'");
        console.log(this.props.listItems);
    }

    createTable(){
        let key = 0;
        return this.props.listItems.mainInformation.map((item) => {
            return <div key={`key_${key++}`}>{`${item.date_register} ${item.id} ${item.message}`}</div>;
        });
    }

    render(){
        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left text-muted">журнал информационных сообщений</Col>
                </Row>
                <Row><Col md={12}>выводятся последние 100 сообщений</Col></Row>
                <br/>
                {this.createTable()}
            </React.Fragment>
        );
    }
}

CreatePageNotificationLog.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageNotificationLog
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));