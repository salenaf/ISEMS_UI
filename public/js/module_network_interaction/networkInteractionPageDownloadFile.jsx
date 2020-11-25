import React from "react";
import ReactDOM from "react-dom";
import { Col, Row, Spinner } from "react-bootstrap";
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
            showSpinner: true,
            showModalWindowListDownload: false,
            showModalWindowShowTaskInformation: false,
            currentTaskID: "",
            listFileDownloadOptions: {
                p: { cs: 0, cn: 0, ccn: 1 },
                slft: [],
                tntf: 0,
            },
        };

        this.userPermission = this.props.listItems.userPermissions;

        this.handlerShowSpinner = this.handlerShowSpinner.bind(this);
        this.handlerShowModalWindowListDownload = this.handlerShowModalWindowListDownload.bind(this);
        this.handlerCloseModalWindowListDownload = this.handlerCloseModalWindowListDownload.bind(this);
        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation=this.handlerCloseModalWindowShowTaskInformation.bind(this);

        this.headerEvents.call(this);
        this.requestEmitter.call(this);
    }

    requestEmitter(){
        this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: { forWidgets: false }});
    }

    headerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "get list tasks files not downloaded"){
                this.setState({ 
                    currentTaskID: data.taskID,
                    listFileDownloadOptions: data.options, 
                });
            }

            this.handlerShowSpinner();

            if((data.type === "filtrationProcessing") || (data.type === "downloadProcessing")){          
                if(data.options.status !== "complete"){
                    return;
                }

                this.props.socketIo.emit("network interaction: get list tasks to download files", { arguments: { forWidgets: false } });
            }
        });
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

    handlerShowSpinner(){
        this.setState({ showSpinner: false });
    }

    render(){
        let showSpinner = (
            <Row>
                <Col md={12}>
                    <CreateBodyDownloadFiles
                        socketIo={this.props.socketIo}
                        currentTaskID={this.state.currentTaskID}
                        listFileDownloadOptions={this.state.listFileDownloadOptions}
                        handlerModalWindowShowTaskTnformation={this.handlerModalWindowShowTaskTnformation} 
                        handlerShowModalWindowListFileDownload={this.handlerShowModalWindowListDownload} />
                </Col>
            </Row>
        );
        if(this.state.showSpinner){
            showSpinner = (
                <Row className="pt-4">
                    <Col md={12}>
                        <Spinner animation="border" role="status" variant="primary">
                            <span className="sr-only text-muted">Загрузка...</span>
                        </Spinner>
                    </Col>
                </Row>
            );
        }

        return (
            <React.Fragment>
                <Row>
                    <Col md={12} className="text-left text-muted">выгрузка файлов</Col>
                </Row>
                {showSpinner}
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