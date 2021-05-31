import React from "react";
import ReactDOM from "react-dom";
import { Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

//import CreateBodyDynamics from "./createBodyDynamics.jsx";
//import ModalWindowShowInformationTask from "../modal_windows/modalWindowShowInformationTask.jsx";

class CreateMainPage extends React.Component {
    constructor(props) {
        super(props);

        this.state = {};

        //        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        //        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        //        this.handlerCloseModalWindowShowTaskInformation = this.handlerCloseModalWindowShowTaskInformation.bind(this);
    }

    handlerModalWindowShowTaskTnformation(data) {
        let objCopy = Object.assign({}, this.state);
        objCopy.shortTaskInformation.sourceID = data.sourceID;
        objCopy.shortTaskInformation.sourceName = data.sourceName;
        objCopy.shortTaskInformation.taskID = data.taskID;
        this.setState(objCopy);

        this.handlerShowModalWindowShowTaskInformation();
    }

    handlerShowModalWindowShowTaskInformation() {
        this.setState({ showModalWindowShowTaskInformation: true });
    }


    handlerCloseModalWindowShowTaskInformation() {
        this.setState({ showModalWindowShowTaskInformation: false });
    }

    render() {
        return (
            <React.Fragment>
                <Row className="pt-3">
                    <Col md={12}>
                        Страница модуля управления структуированной информацией о компьютерных событиях
                    </Col>
                </Row>

            </React.Fragment>
        );
    }
}

CreateMainPage.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
};

ReactDOM.render(<CreateMainPage
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));