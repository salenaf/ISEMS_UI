import React from "react";
import { Badge, Button, Col, Row } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyDynamics from "./createBodyDynamics.jsx";
import ModalWindowAddFilteringTask from "../modalwindows/modalWindowAddFilteringTask.jsx";
import ModalWindowShowTaskFiltraion from "../modalwindows/modalWindowShowTaskFiltraion.jsx";
import ModalWindowListTaskDownloadFiles from "../modalwindows/modalWindowListTaskDownloadFiles.jsx";

export default class CreateBodyFormationTask extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            connectionModuleNI: this.props.connectionModuleNI,
            showModalWindowFiltration: false,
            showModalWindowListDownload: false,
            showModalWindowShowTaskFiltraion: false,
            shortFilteringTaskInformation: { 
                sourceID: 11111, 
                sourceName: "тестовое название" 
            },
        };

        this.handlerEvents.call(this);

        this.handlerButtonSubmitWindowFilter = this.handlerButtonSubmitWindowFilter.bind(this);
        this.handlerButtonSubmitWindowDownload = this.handlerButtonSubmitWindowDownload.bind(this);
        this.handlerShowModalWindowFiltration = this.handlerShowModalWindowFiltration.bind(this);
        this.handlerCloseModalWindowFiltration = this.handlerCloseModalWindowFiltration.bind(this);
        this.handlerShowModalWindowListDownload = this.handlerShowModalWindowListDownload.bind(this);
        this.handlerCloseModalWindowListDownload = this.handlerCloseModalWindowListDownload.bind(this);
        this.handlerShowModalWindowShowTaskFiltraion = this.handlerShowModalWindowShowTaskFiltraion.bind(this);
        this.handlerCloseModalWindowShowTaskFiltraion = this.handlerCloseModalWindowShowTaskFiltraion.bind(this);

        this.handlerButtonStopFiltering = this.handlerButtonStopFiltering.bind(this);
    }

    handlerEvents(){
        this.props.socketIo.on("module NI API", (data) => {
            if(data.type === "connectModuleNI"){
                if(data.options.connectionStatus){
                    this.setState({ "connectionModuleNI": true });
                } else {
                    this.setState({ "connectionModuleNI": false });
                }
            }
        });
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

    handlerButtonStopFiltering(){
        console.log("func 'handlerButtonStopFiltering', START...");
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

    handlerShowModalWindowShowTaskFiltraion(){
        console.log("func 'handlerShowModalWindowShowTaskFiltraion', START...");

        this.setState({ showModalWindowShowTaskFiltraion: true });
    }

    handlerCloseModalWindowShowTaskFiltraion(){
        this.setState({ showModalWindowShowTaskFiltraion: false });
    }

    isDisabledFiltering(){
        //если нет соединения с модулем сетевого взаимодействия
        if(!this.state.connectionModuleNI){
            return "disabled";
        }

        if(!this.props.userPermission.management_tasks_filter.element_settings.create.status){
            return "disabled";
        }      

        return (this.props.userPermission.management_tasks_filter.element_settings.create.status) ? "" : "disabled";
    }

    isDisabledDownload(){
        //если нет соединения с модулем сетевого взаимодействия
        if(!this.state.connectionModuleNI){
            return "disabled";
        }

        return "";
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
                        <Button 
                            variant="outline-primary" 
                            disabled={this.isDisabledDownload.call(this)}
                            onClick={this.handlerShowModalWindowListDownload} 
                            size="sm" 
                            className="ml-1">
                            загрузка <Badge variant="light">0</Badge>
                            <span className="sr-only">unread messages</span>
                        </Button>
                    </Col>
                </Row>
                <CreateBodyDynamics 
                    socketIo={this.props.socketIo}
                    handlerShowModalWindowShowTaskFiltraion={this.handlerShowModalWindowShowTaskFiltraion} />
                <ModalWindowAddFilteringTask 
                    show={this.state.showModalWindowFiltration}
                    onHide={this.handlerCloseModalWindowFiltration}
                    listSources={this.props.listSources}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowFilter} />
                <ModalWindowListTaskDownloadFiles 
                    show={this.state.showModalWindowListDownload}
                    onHide={this.handlerCloseModalWindowListDownload}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowDownload} />
                <ModalWindowShowTaskFiltraion 
                    show={this.state.showModalWindowShowTaskFiltraion}
                    onHide={this.handlerCloseModalWindowShowTaskFiltraion}
                    shortTaskInfo={this.state.shortFilteringTaskInformation}
                    handlerButtonStopFiltering={this.handlerButtonStopFiltering} />
            </React.Fragment>
        );
    }
}

CreateBodyFormationTask.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listSources: PropTypes.object.isRequired,
    userPermission: PropTypes.object.isRequired,
    connectionModuleNI: PropTypes.bool.isRequired,
};