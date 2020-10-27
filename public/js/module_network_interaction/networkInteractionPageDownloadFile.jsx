import React from "react";
import ReactDOM from "react-dom";
import { Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyDownloadFiles from "./createBodyDownloadFiles.jsx";
import ModalWindowShowInformationTask from "../modal_windows/modalWindowShowInformationTask.jsx";
import ModalWindowListTaskDownloadFiles from "../modal_windows/modalWindowListTaskDownloadFiles.jsx";

class CreatePageDownloadFile extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
            showModalWindowListDownload: false,
            showModalWindowShowTaskInformation: false,
        };

        this.userPermission = this.props.listItems.userPermissions;

        this.handlerShowModalWindowListDownload = this.handlerShowModalWindowListDownload.bind(this);
        this.handlerCloseModalWindowListDownload = this.handlerCloseModalWindowListDownload.bind(this);
        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);
    }

    handlerModalWindowShowTaskTnformation(data){
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

    handlerShowModalWindowListDownload(data){
        let objCopy = Object.assign({}, this.state);
        objCopy.shortTaskInformation.sourceID = data.sourceID;
        objCopy.shortTaskInformation.sourceName = data.sourceName;
        objCopy.shortTaskInformation.taskID = data.taskID;
        this.setState(objCopy);

        this.setState({ showModalWindowListDownload: true });
    }

    handlerCloseModalWindowListDownload(){
        this.setState({ showModalWindowListDownload: false });
    }

    render(){
        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left text-muted">выгрузка файлов</Col>
                </Row>
                <Row>
                    <Col md={12}>
                        <CreateBodyDownloadFiles
                            socketIo={this.props.socketIo} 
                            handlerModalWindowShowTaskTnformation={this.handlerModalWindowShowTaskTnformation} 
                            handlerShowModalWindowListFileDownload={this.handlerShowModalWindowListDownload} />
                    </Col>
                </Row>
                <ModalWindowShowInformationTask 
                    show={this.state.showModalWindowShowTaskInformation}
                    onHide={this.handlerCloseModalWindowShowTaskInformation}
                    socketIo={this.props.socketIo}
                    shortTaskInfo={this.state.shortTaskInformation} />
                <ModalWindowListTaskDownloadFiles 
                    show={this.state.showModalWindowListDownload}
                    onHide={this.handlerCloseModalWindowListDownload}
                    socketIo={this.props.socketIo}
                    userPermissionImport={this.userPermission.management_tasks_import.element_settings.resume.status}
                    shortTaskInfo={this.state.shortTaskInformation} />
            </React.Fragment>
        );
    }
}

CreatePageDownloadFile.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listItems: PropTypes.object.isRequired,
}; 

ReactDOM.render(<CreatePageDownloadFile
    socketIo={socket}
    listItems={receivedFromServer} />, document.getElementById("main-page-content"));