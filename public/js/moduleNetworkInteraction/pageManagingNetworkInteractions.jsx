import React from "react";
import { Button, Col, Row, Tab, Tabs } from "react-bootstrap";
import PropTypes from "prop-types";

import CreateBodyDynamics from "./createBodyDynamics.jsx";
import CreateBodySearchTask from "./createBodySearchTask.jsx";
import CreateBodyDownloadFiles from "./createBodyDownloadFiles.jsx";
import ModalWindowAddFilteringTask from "../modalwindows/modalWindowAddFilteringTask.jsx";
import ModalWindowShowInformationTask from "../modalwindows/modalWindowShowInformationTask.jsx";
import ModalWindowListTaskDownloadFiles from "../modalwindows/modalWindowListTaskDownloadFiles.jsx";

export default class PageManagingNetworkInteractions extends React.Component {
    constructor(props){
        super(props);

        this.state = {
            connectionModuleNI: this.props.connectionModuleNI,
            showModalWindowFiltration: false,
            showModalWindowListDownload: false,
            showModalWindowShowTaskInformation: false,
            shortTaskInformation: { 
                sourceID: 0, 
                sourceName: "",
                taskID: "",
            },
        };

        this.handlerButtonSubmitWindowFilter = this.handlerButtonSubmitWindowFilter.bind(this);
        this.handlerShowModalWindowFiltration = this.handlerShowModalWindowFiltration.bind(this);
        this.handlerCloseModalWindowFiltration = this.handlerCloseModalWindowFiltration.bind(this);
        this.handlerButtonSubmitWindowDownload = this.handlerButtonSubmitWindowDownload.bind(this);
        this.handlerShowModalWindowListDownload = this.handlerShowModalWindowListDownload.bind(this);
        this.handlerCloseModalWindowListDownload = this.handlerCloseModalWindowListDownload.bind(this);
        this.handlerModalWindowShowTaskTnformation = this.handlerModalWindowShowTaskTnformation.bind(this);
        this.handlerShowModalWindowShowTaskInformation = this.handlerShowModalWindowShowTaskInformation.bind(this);
        this.handlerCloseModalWindowShowTaskInformation = this.handlerCloseModalWindowShowTaskInformation.bind(this);

        this.handlerEvents.call(this);
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

    handlerShowModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: true });
    }

    handlerCloseModalWindowFiltration(){
        this.setState({ showModalWindowFiltration: false });
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

        //проверяем наличие хотя бы одного параметра в inputValue
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

    handlerButtonSubmitWindowDownload(){
        console.log("func 'handlerButtonSubmitWindowDownload', START...");
    }

    handlerShowModalWindowListDownload(){
        this.setState({ showModalWindowListDownload: true });
    }

    handlerCloseModalWindowListDownload(){
        this.setState({ showModalWindowListDownload: false });
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

    render(){
        return (
            <React.Fragment>
                <Row className="mt-3">
                    <Col md={12} className="text-right">
                        <Button
                            className="mx-1"
                            size="sm"
                            variant="outline-danger"                            
                            disabled={this.isDisabledFiltering.call(this)}
                            onClick={this.handlerShowModalWindowFiltration} >
                            фильтрация
                        </Button>
                        <Button 
                            disabled
                            className="mx-1"
                            size="sm"
                            variant="outline-dark" >                           
                            сетевой калькулятор
                        </Button>
                        <Button
                            disabled
                            className="mx-1"
                            size="sm"
                            variant="outline-dark" >                           
                            декодер
                        </Button>
                    </Col>
                </Row>
                <Row>
                    <Col md={12}>
                        <Tabs defaultActiveKey="procession_task" id="uncontrolled-tab-example">
                            <Tab eventKey="procession_task" title="выполняемые задачи">
                                <CreateBodyDynamics 
                                    socketIo={this.props.socketIo}
                                    handlerModalWindowShowTaskTnformation={this.handlerModalWindowShowTaskTnformation} />
                            </Tab>
                            <Tab eventKey="download_task" title="загрузка файлов">
                                <CreateBodyDownloadFiles
                                    socketIo={this.props.socketIo} />
                            </Tab>
                            <Tab eventKey="search_task" title="поиск">
                                <CreateBodySearchTask />
                            </Tab>
                            <Tab eventKey="statistics_and_analytics" title="статистика и аналитика">
                                {"страница статистики и аналитики"}
                            </Tab>
                            <Tab eventKey="sources_telemetry" title="телеметрия с источников">
                                {"страница телеметрии источников"}
                            </Tab>
                        </Tabs>
                    </Col>
                </Row>                    

                <ModalWindowAddFilteringTask 
                    show={this.state.showModalWindowFiltration}
                    onHide={this.handlerCloseModalWindowFiltration}
                    listSources={this.props.listSources}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowFilter} />
                <ModalWindowListTaskDownloadFiles 
                    show={this.state.showModalWindowListDownload}
                    onHide={this.handlerCloseModalWindowListDownload}
                    handlerButtonSubmit={this.handlerButtonSubmitWindowDownload} />
                <ModalWindowShowInformationTask 
                    show={this.state.showModalWindowShowTaskInformation}
                    onHide={this.handlerCloseModalWindowShowTaskInformation}
                    socketIo={this.props.socketIo}
                    shortTaskInfo={this.state.shortTaskInformation} />
            </React.Fragment>
        );
    }
}

PageManagingNetworkInteractions.propTypes = {
    socketIo: PropTypes.object.isRequired,
    listSources: PropTypes.object.isRequired,
    userPermission: PropTypes.object.isRequired,
    connectionModuleNI: PropTypes.bool.isRequired,
};