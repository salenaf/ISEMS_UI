import React from "react";
import ReactDOM from "react-dom";
import { Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import ModalWindowShowInformationTask from "../modalwindows/modalWindowShowInformationTask.jsx";

class CreatePageSearchTasks extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
            showModalWindowShowTaskInformation: false,
        };

        this.userPermission=this.props.listItems.userPermissions;

        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);
    }

    handlerModalWindowShowTaskTnformation(data){

        console.log("func 'handlerModalWindowShowTaskTnformation'...");
        console.log(data);

        let objCopy = Object.assign({}, this.state);
        objCopy.shortTaskInformation.sourceID = data.sourceID;
        objCopy.shortTaskInformation.sourceName = data.sourceName;
        objCopy.shortTaskInformation.taskID = data.taskID;
        this.setState(objCopy);

        this.handlerShowModalWindowShowTaskInformation();
    }

    handlerShowModalWindowShowTaskInformation(){
        this.setState({ showModalWindowShowTaskInformation: true });
    }


    handlerCloseModalWindowShowTaskInformation(){
        this.setState({ showModalWindowShowTaskInformation: false });
    }

    render(){
        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left text-muted">поиск задач</Col>
                </Row>
                <Row>
                    <Col md={12}>

                    </Col>
                </Row>
                <ModalWindowShowInformationTask 
                    show={this.state.showModalWindowShowTaskInformation}
                    onHide={this.handlerCloseModalWindowShowTaskInformation}
                    socketIo={this.props.socketIo}
                    shortTaskInfo={this.state.shortTaskInformation} />
            </React.Fragment>
        );
    }
}

CreatePageSearchTasks.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageSearchTasks
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));