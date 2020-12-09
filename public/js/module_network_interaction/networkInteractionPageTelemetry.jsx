import React from "react";
import ReactDOM from "react-dom";
import { Button, Col, Form, Row, Table, Tooltip, OverlayTrigger } from "react-bootstrap";
import PropTypes from "prop-types";

class CreatePageTelemetry extends React.Component {
    constructor(props){
        super(props);

        //        this.getListSource = this.getListSource.bind(this);
    
        console.log(this.props.listItems);
    }

    /*    getListSource(){
        return Object.keys(this.props.listSources).sort((a, b) => a < b).map((sourceID, num) => {
            return (
                <option 
                    key={`key_source_${num}_${this.props.listSources[sourceID].id}`} 
                    value={sourceID} >
                    {`${sourceID} ${this.props.listSources[sourceID].shortName}`}
                </option>
            );
        });
    }*/

    render(){
        return (
            <Row>
                <Col md={12}>
        Телеметрия, тестовая страница
                </Col>
            </Row>
        );
    }
}

CreatePageTelemetry.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageTelemetry
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));