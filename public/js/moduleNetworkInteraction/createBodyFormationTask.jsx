import React from "react";
import { Badge, Button, Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyDynamics from "./createBodyDynamics.jsx";
import ModalWindowAddFilteringTask from "../modalwindows/modalWindowAddFilteringTask.jsx";
import ModalWindowListTaskDownloadFiles from "../modalwindows/modalWindowListTaskDownloadFiles.jsx";

export default class CreateBodyFormationTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            showModalWindowFiltration: false,
            showModalWindowListDownload: false,
        };

        this.handlerButtonSubmitWindowFilter = this.handlerButtonSubmitWindowFilter.bind(this);
        this.handlerButtonSubmitWindowDownload = this.handlerButtonSubmitWindowDownload.bind(this);
        this.handlerShowModalWindowFiltration = this.handlerShowModalWindowFiltration.bind(this);
        this.handlerCloseModalWindowFiltration = this.handlerCloseModalWindowFiltration.bind(this);
        this.handlerShowModalWindowListDownload = this.handlerShowModalWindowListDownload.bind(this);
        this.handlerCloseModalWindowListDownload = this.handlerCloseModalWindowListDownload.bind(this);
    }

    handlerButtonSubmitWindowFilter(objTaskInfo){
        let checkExistInputValue = () => {
            let isEmpty = true;

            done:
            for(let et in objTaskInfo.inputValue){
                for(let d in objTaskInfo.inputValue[et]){
                    if(Array.isArray(objTaskInfo.inputValue[et][d]) && objTaskInfo.inputValue[et][d].length > 0){
                        isEmpty = false;

                        break done;  
                    }
                }
            }

            return isEmpty;
        };

        //проверяем наличие хотябы одного параметра в inputValue
        if(checkExistInputValue()){
            return;
        }

        this.props.socketIo.emit("start new filtration task", {
            actionType: "add new task",
            arguments: {
                source: objTaskInfo.source,
                dateTime: {
                    start: +(new Date(objTaskInfo.startDate)),
                    end: +(new Date(objTaskInfo.endDate)),
                },
                networkProtocol: objTaskInfo.networkProtocol,
                inputValue: objTaskInfo.inputValue,
            },
        });

        this.handlerCloseModalWindowFiltration();
    }

    handlerButtonSubmitWindowDownload(){
        console.log("func 'handlerButtonSubmitWindowDownload', START...");
    }


    handlerShowModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: true });
    }

    handlerCloseModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: false });
    }

    handlerShowModalWindowListDownload(){
        this.setState({ showModalWindowListDownload: true });
    }

    handlerCloseModalWindowListDownload(){
        this.setState({ showModalWindowListDownload: false });
    }

    isDisabledFiltering(){
        if(!this.props.userPermission.management_tasks_filter.element_settings.create.status){
            return "disabled";
        }

        return (this.props.userPermission.management_tasks_filter.element_settings.create.status) ? "" : "disabled";
    }

    render(){
        return (
            <React.Fragment>
                <Row className="mt-3 mb-3">
                    <Col sm="8"></Col>
                    <Col className="text-right">
                        <Button 
                            variant="outline-primary" 
                            disabled={this.isDisabledFiltering.call(this)}
                            onClick={this.handlerShowModalWindowFiltration} 
                            size="sm">
                            фильтрация
                        </Button>
                        <Button variant="outline-primary" onClick={this.handlerShowModalWindowListDownload} size="sm" className="ml-1">
                            загрузка <Badge variant="light">0</Badge>
                            <span className="sr-only">unread messages</span>
                        </Button>
                    </Col>
                </Row>
                <CreateBodyDynamics />
                <ModalWindowAddFilteringTask 
                    show={this.state.showModalWindowFiltration}
                    onHide={this.handlerCloseModalWindowFiltration}
                    listSources={this.props.listSources}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowFilter} />
                <ModalWindowListTaskDownloadFiles 
                    show={this.state.showModalWindowListDownload}
                    onHide={this.handlerCloseModalWindowListDownload}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowDownload} />
            </React.Fragment>
        );
    }
}

CreateBodyFormationTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listSources: PropTypes.object.isRequired,
    userPermission: PropTypes.object.isRequired,
};